#!/usr/bin/env bash
# Install Aegis × Burrow.
#
#   curl -fsSL https://raw.githubusercontent.com/alexd-aero/aegis-burrow/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/alexd-aero/aegis-burrow/main/install.sh | bash -s -- --termix
#
# or from a checkout: ./install.sh [--port 4310] [--bind 127.0.0.1] [--termix]
# Options are those of `aegis install` (see bin/aegis).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$here" ] && [ -x "$here/bin/aegis" ] && [ -f "$here/aegis/server.mjs" ]; then
  exec "$here/bin/aegis" install "$@"
fi
REPO="${AEGIS_REPO:-https://github.com/alexd-aero/aegis-burrow}"
REF="${AEGIS_REF:-main}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "  · fetching Aegis × Burrow ($REF)…"
if command -v git >/dev/null 2>&1; then
  git clone -q --depth 1 --branch "$REF" "$REPO" "$tmp/aegis-burrow"
else
  curl -fsSL "$REPO/archive/refs/heads/$REF.tar.gz" | tar -xz -C "$tmp"
  mv "$tmp"/aegis-burrow-* "$tmp/aegis-burrow"
fi
"$tmp/aegis-burrow/bin/aegis" install "$@"
