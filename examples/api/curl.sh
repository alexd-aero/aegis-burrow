#!/usr/bin/env bash
# The Aegis × Burrow API from a shell. Needs curl (and jq, only to make it pretty).
#   AEGIS_URL=https://aegis.example.com AEGIS_KEY=aegis_… ./curl.sh
set -euo pipefail
: "${AEGIS_URL:?set AEGIS_URL to your dashboard, like https://aegis.example.com}"
: "${AEGIS_KEY:?set AEGIS_KEY to an API key (Settings → Developer)}"
API="${AEGIS_URL%/}/__gate/v1"
pretty() { if command -v jq >/dev/null; then jq .; else cat; echo; fi; }
call() {   # call METHOD PATH [JSON]
  curl -sS -X "$1" "$API$2" -H "Authorization: Bearer $AEGIS_KEY" -H "Content-Type: application/json" ${3:+-d "$3"} | pretty
}

echo "== who am I";            call GET /whoami
echo "== status";              call GET /overview
echo "== tunnels";             call GET /tunnels
PORT="${PORT:-8080}"
echo "== publish $PORT behind the login"
call POST /tunnels "{\"port\": $PORT, \"name\": \"API example\", \"access\": \"login\"}"
echo "== make it public";      call PATCH "/tunnels/$PORT" '{"access": "public"}'
echo "== and take it down";    call DELETE "/tunnels/$PORT"
echo "== addons with updates"; call GET /addons/updates
