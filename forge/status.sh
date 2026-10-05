#!/usr/bin/env bash
# Selkies Forge: one JSON line, {"state", "version", "url", "detail"}.
set -u
cd "$(dirname "$0")/.."
s="$(bin/aegis status --json 2>/dev/null)" || true
[ -n "$s" ] || { echo '{"state":"error","detail":"aegis status failed"}'; exit 0; }
get() { printf '%s' "$s" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
state="$(get state)"; ver="$(get version)"; dash="$(get dashboard)"; link="$(get setup_url)"
# Burrow is a module of Aegis: name both while it is on
name="Aegis"; printf '%s' "$s" | grep -q '"burrow":true' && name="Aegis × Burrow"
if printf '%s' "$s" | grep -q '"setup_needed":true'; then
  printf '{"state":"%s","version":"%s","url":"%s","detail":"Open it once to create your login.","name":"%s"}\n' "$state" "$ver" "$link" "$name"
else
  printf '{"state":"%s","version":"%s","url":"%s","detail":"%s","name":"%s"}\n' "$state" "$ver" "$dash" "$dash" "$name"
fi
