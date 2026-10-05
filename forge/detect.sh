#!/usr/bin/env bash
# Selkies Forge: is Aegis × Burrow (or the Aegis it grew from) already on this machine? Exit 0 and say what was
# found (one JSON line), or exit 1. Must be quick and must not change anything.
set -u
disc="${XDG_CONFIG_HOME:-$HOME/.config}/aegis/aegis.json"
[ -f "$disc" ] || exit 1
home="$(sed -n 's/.*"home": *"\([^"]*\)".*/\1/p' "$disc" | head -1)"
code="$(sed -n 's/.*"code": *"\([^"]*\)".*/\1/p' "$disc" | head -1)"
code="${code:-$home/app}"
[ -f "$code/aegis/server.mjs" ] || [ -f "$code/server/server.mjs" ] || exit 1
ver="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$code/package.json" | head -1)"
url="$(sed -n 's/.*"dashboard": *"\([^"]*\)".*/\1/p' "$disc" | head -1)"
printf '{"version":"%s","url":"%s","detail":"Aegis × Burrow %s in %s"}\n' "$ver" "$url" "$ver" "$home"
