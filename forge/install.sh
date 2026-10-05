#!/usr/bin/env bash
# Selkies Forge: install Aegis × Burrow, or upgrade and link the one already here.
#
# Forge runs this from the addon checkout with FORGE_* in the environment
# (see the Selkies Forge addon docs). Settings arrive as
# FORGE_ADDON_SETTING_PORT and FORGE_ADDON_SETTING_TERMIX.
set -euo pipefail
cd "$(dirname "$0")/.."
args=()
if [ "${FORGE_ADDON_ADOPT:-0}" = 1 ]; then
  echo "::phase Linking the Aegis × Burrow already on this machine"
  echo "It is already installed here: upgrading its code in place, keeping the login, domain and tunnels."
else
  echo "::phase Installing Aegis × Burrow"
  args+=(--port "${FORGE_ADDON_SETTING_PORT:-4310}")
  # Answer on the same address as Selkies Forge, so the dashboard opens from
  # wherever the Forge does. The first-run page needs the one-time link.
  case "${FORGE_BIND:-127.0.0.1}" in
    127.0.0.1|localhost|::1|"") ;;
    *) args+=(--bind "$FORGE_BIND") ;;
  esac
fi
[ "${FORGE_ADDON_SETTING_TERMIX:-0}" = 1 ] && args+=(--termix)
bin/aegis install "${args[@]}"
# A fresh install without Burrow: switch the engine off (Settings → Modules,
# or the "Burrow on/off" action, brings it back). Updates leave it as it is.
if [ "${FORGE_ADDON_ADOPT:-0}" != 1 ] && [ "${FORGE_ADDON_UPDATE:-0}" != 1 ] && [ "${FORGE_ADDON_SETTING_BURROW:-1}" = 0 ]; then
  bin/aegis burrow off
fi
