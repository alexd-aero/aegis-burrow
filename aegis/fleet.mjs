// Machine management: the other machines you own, linked to this one.
//
// Off until you switch it on (Settings -> Modules). Then:
//
//   1. Aegis makes itself one SSH key (data/fleet/id_ed25519), once.
//   2. "Link a machine" hands you one command. You run it on the other
//      machine; it appends that public key to the invoking user's
//      authorized_keys and tells this Aegis where it lives (hostname, the
//      addresses it answers on, its SSH port). Nothing else leaves it.
//   3. From then on Aegis can reach it: read what it runs, what it is made
//      of, install apps on it, move an app's data between machines, and keep
//      a clone of itself there that takes over if this host goes down.
//
// A machine is reached at whatever address you gave: a domain this Aegis
// serves, a LAN address, a subnet address, a public address, a Tailscale
// name, a bare hostname. Only the address and port are kept; the key is the
// only credential, and "Forget" takes it off the machine again.
//
// Everything here shells out to the system ssh/scp: no new dependencies, and
// whatever the machine's own ssh config says (ProxyJump, a Tailscale name)
// keeps working. Remote scripts are fed to `bash -s` on stdin, never
// interpolated into a command line.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { hostname } from "node:os";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readJson, writeJson } from "./config.mjs";

export class FleetError extends Error {}
const fail = (m) => { throw new FleetError(m); };

const TOKEN_TTL_MS = 30 * 60 * 1000;      // a link command is good for half an hour
const MAX_MACHINES = 64;
const ID_RE = /^m-[0-9a-f]{10}$/;
// an address we are willing to ssh to: a host name, a domain or an IPv4
const ADDR_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/;
const V4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

// One address, as ssh wants it: ::ffff: mapping dropped, IPv6 in brackets.
// Anything else -> null.
export function normAddr(v) {
  let a = String(v ?? "").trim().replace(/^::ffff:/i, "");
  if (a.startsWith("[") && a.endsWith("]")) a = a.slice(1, -1);
  if (!a) return null;
  if (a.includes(":")) return /^[0-9a-fA-F:]{2,45}$/.test(a) ? `[${a}]` : null;
  return ADDR_RE.test(a) ? a : null;
}
// A bare word is only an address if the machine said that is its name: a
// hostname with no dots is otherwise just a word that got through the split.
const usable = (a, host) => !!a && (V4_RE.test(a) || a.startsWith("[") || a.includes(".") || a === host);
const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;

export const APPS = {
  "aegis-burrow": { name: "Aegis × Burrow", logo: "/__gate/logos/aegis-burrow.svg" },
  "selkies-forge": { name: "Selkies Forge", logo: "/__gate/logos/forge.svg" },
  bulwark: { name: "Bulwark", logo: "/__gate/logos/bulwark.svg" },
  termix: { name: "Termix", logo: "/__gate/logos/termix.svg" },
};

// ------------------------------------------------------------------ jobs
// Same shape as the addon host's jobs, so the dashboard can poll them the
// same way: /__gate/api/fleet/jobs/<id>?since=<n>.
export class Job {
  constructor(kind, label, mid) {
    Object.assign(this, { id: randomBytes(6).toString("hex"), mid, kind, label, state: "running", phase: label,
                          progress: 0.02, lines: [], base: 0, started: Date.now(), finished: null, result: null, error: null });
  }
  log(line, cls) {
    this.lines.push({ t: Date.now(), line: String(line).slice(0, 2000), cls: cls || "" });
    if (this.lines.length > 1200) { this.lines.splice(0, 400); this.base += 400; }
  }
  step(phase, progress) { this.phase = phase; if (progress != null) this.progress = progress; this.log(phase, "step"); }
  view(since = 0) {
    const from = Math.max(0, since - this.base);
    return { id: this.id, mid: this.mid, kind: this.kind, label: this.label, state: this.state, phase: this.phase,
             progress: this.progress, started: this.started, finished: this.finished, result: this.result,
             error: this.error, next: this.base + this.lines.length, lines: this.lines.slice(from) };
  }
}

// ------------------------------------------------------------------ running things
export function run(cmd, args, { input, timeout = 30000, onLine } = {}) {
  return new Promise((resolve) => {
    let p;
    try { p = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] }); }
    catch (e) { return resolve({ code: 127, out: "", err: e.message }); }
    let out = "", err = "", rest = "", killed = false;
    const timer = setTimeout(() => { killed = true; try { p.kill("SIGKILL"); } catch { /* gone */ } }, timeout);
    p.stdout.on("data", (c) => {
      out += c;
      if (out.length > 6 << 20) { killed = true; p.kill("SIGKILL"); }
      if (onLine) { rest += c; const parts = rest.split("\n"); rest = parts.pop(); for (const l of parts) onLine(l); }
    });
    p.stderr.on("data", (c) => { err += c; if (err.length > 1 << 20) err = err.slice(-(1 << 20)); });
    p.on("error", (e) => { clearTimeout(timer); resolve({ code: 127, out: out.trim(), err: e.message }); });
    p.on("close", (code) => {
      clearTimeout(timer);
      if (onLine && rest) onLine(rest);
      resolve({ code: killed ? 124 : (code ?? 1), out: out.trim(), err: (killed ? "timed out" : err).trim() });
    });
    try { p.stdin.end(input == null ? "" : input); } catch { /* already gone */ }
  });
}

// ------------------------------------------------------------------ probe
// One pass over the machine: what it is, how loaded it is, what runs on it.
// Sections are printed between ==markers== and parsed below; nothing here
// needs root, and every command that may be missing is guarded.
export const PROBE = String.raw`
sec() { printf '\n==%s==\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
sec host
echo "hostname=$(hostname 2>/dev/null)"
echo "user=$(id -un 2>/dev/null)"
echo "uid=$(id -u 2>/dev/null)"
echo "home=$HOME"
echo "uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "now=$(date +%s)"
sec os
echo "kernel=$(uname -r 2>/dev/null)"
echo "arch=$(uname -m 2>/dev/null)"
echo "system=$(uname -s 2>/dev/null)"
PRETTY_NAME=""; ID=""; VERSION_ID=""
. /etc/os-release 2>/dev/null || true
echo "pretty=$PRETTY_NAME"; echo "distro=$ID"; echo "version=$VERSION_ID"
if [ -r /proc/device-tree/model ]; then echo "model=$(tr -d '\0' < /proc/device-tree/model)"
elif [ -r /sys/devices/virtual/dmi/id/product_name ]; then echo "model=$(cat /sys/devices/virtual/dmi/id/product_name)"; fi
if have systemd-detect-virt; then echo "virt=$(systemd-detect-virt 2>/dev/null)"; fi
sec cpu
echo "cores=$(nproc 2>/dev/null)"
echo "model=$(awk -F': ' '/^(model name|Model|Hardware)/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
echo "load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
for t in /sys/class/thermal/thermal_zone0/temp; do [ -r "$t" ] && echo "temp=$(cat "$t")"; done
sec mem
awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/{gsub(":","",$1); print tolower($1)"="$2}' /proc/meminfo 2>/dev/null
sec disk
df -Pk / "$HOME" 2>/dev/null | awk 'NR>1 && !seen[$6]++ {print $6"|"$2"|"$3"|"$4}'
sec net
if have ip; then ip -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'
else hostname -I 2>/dev/null | tr ' ' '\n'; fi
sec ssh
p=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
[ -n "$p" ] && echo "port=$p"
if have ss; then ss -H -ltn 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ',' | sed 's/^/listening=/;s/,$//'; fi
sec docker
if have docker && docker info >/dev/null 2>&1; then
  docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>/dev/null | head -60
  echo "__ok__"
fi
sec units
if have systemctl; then
  systemctl list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null | awk '{print $1}' | head -120
  systemctl --user list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null | awk '{print "user:"$1}' | head -60
fi
sec apps
for f in "$HOME/.config/aegis/aegis.json" "$HOME/.config/aegis/integrations/selkies-forge.json" "$HOME/.config/bulwark/bulwark.json"; do
  [ -r "$f" ] && { echo "--$f"; head -c 4000 "$f"; echo; }
done
[ -d "$HOME/.selkies-forge" ] && echo "--dir:selkies-forge=$HOME/.selkies-forge"
[ -d "$HOME/.local/share/bulwark" ] && echo "--dir:bulwark=$HOME/.local/share/bulwark"
for f in "$HOME"/.config/aegis/programs/*.json; do
  [ -r "$f" ] && { echo "--prog:$f"; head -c 2000 "$f"; echo; }
done
sec end
`;

function sections(out) {
  const map = {};
  let cur = null;
  for (const line of String(out).split("\n")) {
    const m = /^==([a-z]+)==$/.exec(line.trim());
    if (m) { cur = m[1]; map[cur] = []; continue; }
    if (cur) map[cur].push(line);
  }
  return Object.fromEntries(Object.entries(map).map(([k, v]) => [k, v.join("\n").trim()]));
}
function kv(block) {
  const out = {};
  for (const line of String(block || "").split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };

// What the probe saw -> what the dashboard shows.
export function readProbe(raw) {
  const s = sections(raw);
  if (!("end" in s)) fail("the machine answered, but not with what we asked for");
  const host = kv(s.host), os = kv(s.os), cpu = kv(s.cpu), mem = kv(s.mem), ssh = kv(s.ssh);
  const disks = (s.disk || "").split("\n").filter(Boolean).map((l) => {
    const [mount, total, used, free] = l.split("|");
    return { mount, total: num(total) * 1024, used: num(used) * 1024, free: num(free) * 1024 };
  });
  const addresses = (s.net || "").split("\n").map((a) => a.trim()).filter((a) => a && a !== "127.0.0.1" && a !== "::1");
  const docker = (s.docker || "").includes("__ok__")
    ? (s.docker || "").split("\n").filter((l) => l && l !== "__ok__").map((l) => {
        const [name, image, status, ports] = l.split("|");
        return { name, image, status, ports: (ports || "").slice(0, 200) };
      })
    : null;
  const units = (s.units || "").split("\n").map((u) => u.trim()).filter(Boolean);
  const files = {};
  let key = null, buf = [];
  for (const line of (s.apps || "").split("\n")) {
    const m = /^--(.+)$/.exec(line);
    if (m) { if (key) files[key] = buf.join("\n"); key = m[1]; buf = []; continue; }
    buf.push(line);
  }
  if (key) files[key] = buf.join("\n");

  const memTotal = num(mem.memtotal) * 1024, memFree = num(mem.memavailable) * 1024;
  return {
    host: { hostname: host.hostname || "", user: host.user || "", uid: num(host.uid), home: host.home || "", uptime: num(host.uptime) },
    os: { pretty: os.pretty || os.system || "", distro: os.distro || "", kernel: os.kernel || "", arch: os.arch || "",
          model: os.model || "", virt: os.virt && os.virt !== "none" ? os.virt : null },
    cpu: { cores: num(cpu.cores), model: cpu.model || "", load: (cpu.load || "").split(/\s+/).map(num).filter((n) => n != null),
           tempC: cpu.temp ? Math.round(num(cpu.temp) / (num(cpu.temp) > 1000 ? 1000 : 1)) : null },
    mem: { total: memTotal, free: memFree, used: memTotal && memFree ? memTotal - memFree : null },
    disks, addresses,
    ssh: { port: num(ssh.port) || 22, listening: (ssh.listening || "").split(",").map(num).filter(Boolean) },
    docker, units, apps: foundApps(files, docker, units, host.home || ""),
  };
}

// The apps Aegis knows how to work with, read off their own drop-in files;
// then whatever else is running, so the panel is honest about the rest.
function foundApps(files, docker, units, home) {
  const out = [];
  const j = (p) => { try { return JSON.parse(files[p]); } catch { return null; } };
  const a = j(`${home}/.config/aegis/aegis.json`);
  if (a) out.push({ id: "aegis-burrow", name: APPS["aegis-burrow"].name, version: a.version || null, url: a.dashboard || a.url || null,
                    home: a.home || null, code: a.code || null, cli: a.cli || null,
                    service: a.service?.name || null, scope: a.service?.scope || null, data: a.home || null });
  const f = j(`${home}/.config/aegis/integrations/selkies-forge.json`);
  const fdir = files[`dir:selkies-forge=${home}/.selkies-forge`] !== undefined
    || Object.keys(files).some((k) => k.startsWith("dir:selkies-forge="));
  if (f || fdir) {
    const dir = Object.keys(files).find((k) => k.startsWith("dir:selkies-forge="));
    out.push({ id: "selkies-forge", name: APPS["selkies-forge"].name, version: f?.version || null, url: f?.url || null,
               home: f?.home || (dir ? dir.split("=")[1] : null), data: f?.home || (dir ? dir.split("=")[1] : null),
               service: units.find((u) => /^(user:)?selkies-forge\.service$/.test(u)) || null });
  }
  const bdir = Object.keys(files).find((k) => k.startsWith("dir:bulwark="));
  const b = j(`${home}/.config/bulwark/bulwark.json`);
  if (b || bdir) out.push({ id: "bulwark", name: APPS.bulwark.name, version: null, url: b?.url || null,
                            home: b?.home || (bdir ? bdir.split("=")[1] : null), data: b?.home || (bdir ? bdir.split("=")[1] : null),
                            service: units.find((u) => /^(user:)?bulwark\.service$/.test(u)) || null });
  const t = (docker || []).find((c) => /termix/i.test(c.name) || /termix/i.test(c.image));
  if (t) out.push({ id: "termix", name: APPS.termix.name, version: null, url: null, container: t.name,
                    status: t.status, ports: t.ports, data: null });
  // programs an addon installed through Fleet: the note Fleet left beside them (fleet-ops.mjs)
  for (const [k, v] of Object.entries(files)) {
    if (!k.startsWith("prog:")) continue;
    let p = null; try { p = JSON.parse(v); } catch { continue; }
    if (p && typeof p.id === "string" && typeof p.name === "string" && !out.some((a) => a.id === p.id)) {
      out.push({ id: p.id.slice(0, 80), name: p.name.slice(0, 80), version: p.version ? String(p.version).slice(0, 40) : null,
                 url: typeof p.url === "string" ? p.url.slice(0, 300) : null, program: true, data: null });
    }
  }
  return out;
}

// ------------------------------------------------------------------ the fleet
// How often every linked machine is looked at in the background (one quick
// SSH "echo"), and how many misses in a row make it "not answering". One slow
// answer under load is not a machine going down.
export const BEAT_MS = 60000;
export const MISSES_DOWN = 3;
export const isUp = (m, now = Date.now()) => !!m.lastSeen && (m.misses || 0) < MISSES_DOWN && now - m.lastSeen < (MISSES_DOWN + 2) * BEAT_MS;

// The query Termix opens with: ?view=terminal&hostId=7 opens straight into a
// terminal on that host (Termix's standalone views). Anything else is dropped.
export function termixQuery(params) {
  const q = new URLSearchParams();
  const view = params.get("view"), hid = params.get("hostId");
  if (/^(terminal|file-manager|server-stats|tunnels|docker)$/.test(view || "")) q.set("view", view);
  if (q.has("view") && /^\d{1,9}$/.test(hid || "")) q.set("hostId", hid);
  return q.toString() ? `?${q}` : "";
}

export class Fleet {
  // dir:   AEGIS_HOME/data/fleet  (the key, known_hosts, transfers)
  // file:  AEGIS_HOME/data/fleet.json (machines, pending links)
  constructor({ settings, dir, file, log, version, notify, dashboards }) {
    Object.assign(this, { settings, dir, file, version, notify: notify || (() => {}),
                          dashboards: dashboards || (() => []), log: log || console.log });
    this.jobs = new Map();
    this.probing = new Map();         // id -> promise, so two tabs don't probe twice
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  // ---------------- on or off
  enabled() { return !!(this.settings.get("fleet") || {}).enabled; }
  setEnabled(on) {
    const cur = this.settings.get("fleet") || {};
    this.settings.set({ fleet: { ...cur, enabled: !!on } });
    this.log("fleet:", on ? "on" : "off");
    return this.enabled();
  }
  need() { if (!this.enabled()) fail("Machine management is off. Settings -> Modules switches it on."); }

  // ---------------- the registry
  load() { return readJson(this.file, { machines: [], pending: {} }); }
  save(db) { writeJson(this.file, { spec: 1, ...db }); }
  list() { return this.load().machines; }
  get(id) {
    const m = this.list().find((x) => x.id === id);
    if (!m) fail("No such machine.");
    return m;
  }
  patch(id, p) {
    const db = this.load();
    const i = db.machines.findIndex((x) => x.id === id);
    if (i < 0) fail("No such machine.");
    db.machines[i] = { ...db.machines[i], ...p };
    this.save(db);
    return db.machines[i];
  }

  // ---------------- our key
  keyPath() { return join(this.dir, "id_ed25519"); }
  async publicKey() {
    const pub = `${this.keyPath()}.pub`;
    if (!existsSync(pub)) {
      const r = await run("ssh-keygen", ["-t", "ed25519", "-N", "", "-q", "-f", this.keyPath(),
                                         "-C", `aegis-fleet@${hostname()}`], { timeout: 20000 });
      if (r.code !== 0 || !existsSync(pub)) fail(`Could not make an SSH key: ${r.err || r.out || "ssh-keygen is missing"}`);
      try { chmodSync(this.keyPath(), 0o600); } catch { /* best effort */ }
      this.log("fleet: made an ssh key");
    }
    return readFileSync(pub, "utf8").trim();
  }

  // ---------------- linking a machine
  // The command is run on the other machine. It is good once, for half an
  // hour, and only tells us what the machine itself reports.
  async invite({ base, label }) {
    this.need();
    if (this.list().length >= MAX_MACHINES) fail(`That is already ${MAX_MACHINES} machines.`);
    const url = this.baseUrl(base);
    const pub = await this.publicKey();
    const db = this.load();
    const now = Date.now();
    db.pending = Object.fromEntries(Object.entries(db.pending || {}).filter(([, p]) => p.expires > now).slice(-8));
    const token = randomBytes(24).toString("base64url");
    db.pending[token] = { created: now, expires: now + TOKEN_TTL_MS, label: String(label || "").slice(0, 60) || null, base: url };
    this.save(db);
    return { token, expires: now + TOKEN_TTL_MS, base: url, publicKey: pub,
             command: `curl -fsSL ${JSON.stringify(`${url}/__gate/fleet/join?t=${token}`)} | sh`,
             manual: `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo ${JSON.stringify(pub)} >> ~/.ssh/authorized_keys` };
  }

  // Which address of ours the other machine should call back on. The browser
  // offers the one it is using; we only take an address this gate answers to.
  baseUrl(base) {
    let u;
    try { u = new URL(String(base || "")); } catch { fail("That is not an address this gate answers on."); }
    if (!/^https?:$/.test(u.protocol)) fail("The link address must be http or https.");
    const ok = new Set(this.dashboards().map((h) => String(h).toLowerCase()));
    const host = u.hostname.toLowerCase();
    if (ok.size && !ok.has(host) && !/^(\d{1,3}\.){3}\d{1,3}$/.test(host) && host !== "localhost") {
      fail(`${u.hostname} is not one of this gate's addresses.`);
    }
    return u.origin;
  }

  pending(token) {
    const p = (this.load().pending || {})[String(token || "")];
    return p && p.expires > Date.now() ? p : null;
  }
  dropPending(token) {
    const db = this.load();
    if (db.pending) { delete db.pending[token]; this.save(db); }
  }

  // The script the command downloads. It is shown in the dashboard before you
  // run it, and it does exactly this and nothing else.
  joinScript(token, base) {
    const url = `${base}/__gate/fleet/join?t=${token}`;
    const key = readFileSync(`${this.keyPath()}.pub`, "utf8").trim();
    return `#!/bin/sh
# Links this machine to the Aegis x Burrow dashboard at ${base}
# It adds one public key to ~/.ssh/authorized_keys for the user running it,
# then tells that dashboard this machine's name, addresses and SSH port.
# Nothing else is sent, and no password is asked for or stored.
set -eu
KEY=${JSON.stringify(key)}
BASE=${JSON.stringify(base)}
TOKEN=${JSON.stringify(token)}

printf 'Linking %s to %s\\n' "$(hostname)" "$BASE"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"
if grep -qF "$KEY" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
  echo "  the key is already here"
else
  printf '%s\\n' "$KEY" >> "$HOME/.ssh/authorized_keys"
  echo "  key added to ~/.ssh/authorized_keys"
fi

PORT=22
if [ -r /etc/ssh/sshd_config ]; then
  P=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
  [ -n "\${P:-}" ] && PORT=$P
fi
if command -v ss >/dev/null 2>&1 && ! ss -H -ltn 2>/dev/null | awk '{print $4}' | sed 's/.*://' | grep -qx "$PORT"; then
  echo "  warning: nothing is listening on port $PORT - is the SSH server installed and running?"
fi

ADDRS=$(ip -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}' | head -12 | tr '\\n' ' ' \\
        || hostname -I 2>/dev/null | head -c 300)
ARCH=$(uname -m 2>/dev/null || echo unknown)
OS=$(. /etc/os-release 2>/dev/null; echo "\${PRETTY_NAME:-$(uname -s)}")

Q() { printf '%s' "$1" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g'; }
BODY=$(printf '{"hostname":"%s","user":"%s","port":%s,"addresses":"%s","arch":"%s","os":"%s"}' \\
  "$(Q "$(hostname)")" "$(Q "$(id -un)")" "$PORT" "$(Q "$ADDRS")" "$(Q "$ARCH")" "$(Q "$OS")")

echo "  telling $BASE where to find this machine"
if command -v curl >/dev/null 2>&1; then
  OUT=$(curl -fsSL -X POST -H 'Content-Type: application/json' --data "$BODY" "$BASE/__gate/fleet/claim?t=$TOKEN" || echo FAILED)
elif command -v wget >/dev/null 2>&1; then
  OUT=$(wget -qO- --header='Content-Type: application/json' --post-data="$BODY" "$BASE/__gate/fleet/claim?t=$TOKEN" || echo FAILED)
else
  echo "  neither curl nor wget is here; open ${url} on a machine that has one" >&2; exit 1
fi
case "$OUT" in
  FAILED|"") echo "  could not reach $BASE - is this machine able to open it?" >&2; exit 1 ;;
  *error*) echo "  the dashboard said: $OUT" >&2; exit 1 ;;
esac
echo "Done. The machine now shows up under Burrow -> Machines."
`;
  }

  // The machine called back. Register it, then prove we can get in.
  async claim(token, facts, ip) {
    this.need();
    const p = this.pending(token);
    if (!p) fail("That link command has expired. Make a new one.");
    const host = String(facts.hostname || "").trim().slice(0, 100);
    const user = String(facts.user || "").trim();
    const port = Math.max(1, Math.min(65535, Math.round(Number(facts.port) || 22)));
    if (!USER_RE.test(user)) fail("That machine did not say which user to use.");
    const addrs = String(facts.addresses || "").split(/[\s,]+/).map(normAddr).filter((a) => usable(a, host)).slice(0, 12);
    const candidates = [...new Set([...addrs, normAddr(ip), normAddr(host)].filter((a) => usable(a, host)))];
    if (!candidates.length) fail("That machine gave no address we could use.");
    this.dropPending(token);

    const db = this.load();
    const id = "m-" + randomUUID().replace(/-/g, "").slice(0, 10);
    const m = {
      id, name: p.label || host || candidates[0], hostname: host,
      address: candidates[0], candidates, port, user,
      os: String(facts.os || "").slice(0, 80), arch: String(facts.arch || "").slice(0, 20),
      addedAt: Date.now(), addedFrom: ip || null, lastSeen: null, lastError: null,
      standby: false, probe: null, probedAt: null,
    };
    db.machines.push(m);
    this.save(db);
    this.log("fleet: claimed", id, host, candidates.join(","));
    // Try every address it gave us and keep the first that answers.
    this.verify(id).catch((e) => this.log("fleet: verify", id, e.message));
    return { ok: true, id, name: m.name };
  }

  // Add one by hand: the key has to be there already (the command above, or
  // the one line the dashboard shows).
  async addManual({ address, user, port, name }) {
    this.need();
    const addr = normAddr(String(address || "").trim().replace(/^\w+:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, ""));
    if (!addr) fail("That is not an address or hostname.");
    if (!USER_RE.test(String(user || "").trim())) fail("That is not a user name.");
    if (this.list().length >= MAX_MACHINES) fail(`That is already ${MAX_MACHINES} machines.`);
    const db = this.load();
    const id = "m-" + randomUUID().replace(/-/g, "").slice(0, 10);
    const m = { id, name: String(name || "").slice(0, 60) || addr, hostname: "", address: addr, candidates: [addr],
                port: Math.max(1, Math.min(65535, Math.round(Number(port) || 22))), user: String(user).trim(),
                os: "", arch: "", addedAt: Date.now(), lastSeen: null, lastError: null, standby: false, probe: null, probedAt: null };
    db.machines.push(m);
    this.save(db);
    try { await this.verify(id); } catch (e) { this.forget(id, false).catch(() => {}); throw e; }
    return { ok: true, id };
  }

  // ---------------- reaching it
  opts() {
    return ["-i", this.keyPath(), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", `UserKnownHostsFile=${join(this.dir, "known_hosts")}`, "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
            "-o", "LogLevel=ERROR"];
  }
  sshArgs(m) { return [...this.opts(), "-p", String(m.port), `${m.user}@${m.address}`]; }
  scpArgs(m) { return [...this.opts(), "-P", String(m.port)]; }

  // Feed a script to bash on the far side. Never builds a command line out of
  // anything you typed.
  async ssh(m, script, { timeout = 45000, onLine } = {}) {
    if (!existsSync(this.keyPath())) await this.publicKey();
    const r = await run("ssh", [...this.sshArgs(m), "--", "bash -s"], { input: script, timeout, onLine });
    if (r.code === 124) fail(`${m.name} did not answer in time.`);
    if (r.code === 255 || (r.code === 127 && /ENOENT|not found/i.test(r.err))) {
      fail(sshWhy(r.err) || `Could not reach ${m.address}:${m.port}: ${r.err.split("\n").pop() || "no route"}`);
    }
    return r;
  }
  async copyTo(m, localPath, remotePath, timeout = 10 * 60000) {
    const r = await run("scp", [...this.scpArgs(m), localPath, `${m.user}@${m.address}:${remotePath}`], { timeout });
    if (r.code !== 0) fail(`Copying to ${m.name} failed: ${r.err.split("\n").pop() || r.out}`);
    return true;
  }

  // Walk the addresses the machine gave us until one lets us in, then probe.
  async verify(id) {
    const m = this.get(id);
    const tries = [m.address, ...(m.candidates || [])].filter((a, i, all) => a && all.indexOf(a) === i);
    let last = null;
    for (const address of tries) {
      const r = await run("ssh", [...this.sshArgs({ ...m, address }), "--", "echo aegis-ok"], { timeout: 20000 });
      if (r.code === 0 && r.out.includes("aegis-ok")) {
        this.patch(id, { address, lastSeen: Date.now(), lastError: null, misses: 0 });
        await this.probe(id).catch(() => {});
        return this.get(id);
      }
      last = sshWhy(r.err) || r.err.split("\n").filter(Boolean).pop() || `exit ${r.code}`;
    }
    this.patch(id, { lastError: last, misses: MISSES_DOWN });
    fail(`Could not get in: ${last}`);
  }

  async probe(id, { fresh = false } = {}) {
    const m = this.get(id);
    if (!fresh && m.probe && Date.now() - (m.probedAt || 0) < 20000) return m;
    if (this.probing.has(id)) return this.probing.get(id);
    const work = (async () => {
      const r = await this.ssh(m, PROBE, { timeout: 60000 });
      if (r.code !== 0 && !r.out.includes("==end==")) fail(r.err.split("\n").pop() || `the probe failed (exit ${r.code})`);
      const probe = readProbe(r.out);
      const patch = { probe, probedAt: Date.now(), lastSeen: Date.now(), lastError: null, misses: 0,
                      hostname: probe.host.hostname || m.hostname, os: probe.os.pretty || m.os, arch: probe.os.arch || m.arch };
      // keep every address it answers on, so a changed LAN address still finds it
      const cands = [...new Set([m.address, ...probe.addresses.map(normAddr), ...(m.candidates || [])])].filter(Boolean).slice(0, 16);
      patch.candidates = cands;
      return this.patch(id, patch);
    })().catch((e) => {
      // a probe that times out on a busy machine is not the machine going away:
      // the heartbeat decides whether it answers
      try { this.patch(id, { lastError: e.message }); } catch { /* forgotten meanwhile */ }
      throw e;
    }).finally(() => this.probing.delete(id));
    this.probing.set(id, work);
    return work;
  }

  // One cheap "are you there" per machine, a few at a time. A machine is only
  // marked down after MISSES_DOWN of these fail in a row.
  async beat({ at = 4 } = {}) {
    if (!this.enabled() || this._beating) return;
    this._beating = true;
    try {
      const queue = this.list().filter((m) => !this.probing.has(m.id));
      const one = async (m) => {
        const r = await run("ssh", [...this.sshArgs(m), "--", "echo aegis-ok"], { timeout: 20000 });
        let cur;
        try { cur = this.get(m.id); } catch { return; }                         // forgotten meanwhile
        if (r.code === 0 && r.out.includes("aegis-ok")) {
          if (!isUp(cur)) this.log("fleet:", m.name, "answers again");
          this.patch(m.id, { lastSeen: Date.now(), lastError: null, misses: 0 });
        } else {
          const misses = (cur.misses || 0) + 1;
          const why = sshWhy(r.err) || r.err.split("\n").filter(Boolean).pop() || `exit ${r.code}`;
          this.patch(m.id, { misses, ...(misses >= MISSES_DOWN ? { lastError: why } : {}) });
          if (misses === MISSES_DOWN) {
            this.log("fleet:", m.name, "stopped answering:", why);
            this.notify("fleet", { level: "warn", key: `down-${m.id}`, title: `${m.name} is not answering`,
                                   body: `${MISSES_DOWN} checks in a row got no answer over SSH (${why}).`, link: "/__gate/tunnels#/machines" });
          }
        }
      };
      const workers = Array.from({ length: Math.min(at, queue.length) }, async () => {
        for (let m; (m = queue.shift());) await one(m).catch((e) => this.log("fleet: beat", m.name, e.message));
      });
      await Promise.all(workers);
    } finally { this._beating = false; }
  }
  startBeat() {
    if (this.beatTimer) return;
    this.beatTimer = setInterval(() => this.beat().catch(() => {}), BEAT_MS);
    this.beatTimer.unref?.();
    setTimeout(() => this.beat().catch(() => {}), 5000).unref?.();
  }
  stopBeat() { clearInterval(this.beatTimer); this.beatTimer = null; }

  // ---------------- leaving
  // Takes our key off the machine when it still answers, then drops it.
  async forget(id, revoke = true) {
    const m = this.get(id);
    let removed = false, why = null;
    if (revoke) {
      try {
        const pub = await this.publicKey();
        const r = await this.ssh(m, `set -eu
f="$HOME/.ssh/authorized_keys"
[ -f "$f" ] || exit 0
grep -vxF ${sq(pub)} "$f" > "$f.aegis-tmp" && mv "$f.aegis-tmp" "$f" && chmod 600 "$f"
echo removed`, { timeout: 25000 });
        removed = r.out.includes("removed");
      } catch (e) { why = e.message; }
    }
    const db = this.load();
    db.machines = db.machines.filter((x) => x.id !== id);
    this.save(db);
    this.log("fleet: forgot", id, removed ? "(key removed)" : "(key left in place)");
    return { ok: true, removed, why };
  }

  rename(id, name) {
    const n = String(name || "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, 60);
    if (!n) fail("A machine needs a name.");
    return this.patch(id, { name: n });
  }

  // ---------------- what the dashboard sees
  view() {
    const machines = this.list().map((m) => this.cardOf(m));
    return { enabled: this.enabled(), machines, hub: this.hub(), jobs: [...this.jobs.values()].filter((j) => j.state === "running").map((j) => j.view()) };
  }
  cardOf(m) {
    const p = m.probe;
    return {
      id: m.id, name: m.name, hostname: m.hostname, address: m.address, port: m.port, user: m.user,
      os: m.os, arch: m.arch, standby: !!m.standby, addedAt: m.addedAt, lastSeen: m.lastSeen, lastError: m.lastError,
      probedAt: m.probedAt, candidates: m.candidates || [], misses: m.misses || 0,
      termix: m.termix ? { hostId: m.termix.hostId ?? null, at: m.termix.at || null } : null,
      standbyState: m.standbyState ? { at: m.standbyState.at, url: m.standbyState.url, interval: m.standbyState.interval, misses: m.standbyState.misses } : null,
      up: isUp(m),
      apps: (p?.apps || []).map((a) => ({ id: a.id, name: a.name, version: a.version, url: a.url })),
      specs: p ? { cores: p.cpu.cores, mem: p.mem.total, model: p.os.model || p.cpu.model, disk: p.disks[0] || null } : null,
      usage: p ? { load: p.cpu.load[0] ?? null, cores: p.cpu.cores, memUsed: p.mem.used, memTotal: p.mem.total,
                   tempC: p.cpu.tempC, uptime: p.host.uptime, disk: p.disks[0] || null } : null,
    };
  }
  // This machine, drawn in the middle of the graph.
  hub() {
    return { id: "self", name: this.settings.get("title") || "Aegis", hostname: hostname(), role: "hub",
             version: this.version, address: "this machine", up: true };
  }
  detail(id) {
    const m = this.get(id);
    return { ...this.cardOf(m), probe: m.probe };
  }

  // Where an app lives, across every machine: what the chooser offers.
  whereIs(appId) {
    const out = [];
    for (const m of this.list()) {
      const a = (m.probe?.apps || []).find((x) => x.id === appId);
      if (a) out.push({ machine: m.id, name: m.name, address: m.address, url: a.url, version: a.version,
                        up: isUp(m) });
    }
    return out;
  }

  // ---------------- jobs
  // mid is the machine (or machines) the job holds: a second job on any of
  // them waits until this one is done.
  start(kind, label, mid, work) {
    const mine = [mid].flat();
    for (const j of this.jobs.values()) {
      if (j.state === "running" && [j.mid].flat().some((x) => mine.includes(x))) fail(`That machine is busy: ${j.label}.`);
    }
    const job = new Job(kind, label, mine.length === 1 ? mine[0] : mine);
    this.jobs.set(job.id, job);
    for (const [jid, j] of this.jobs) if (j.state !== "running" && Date.now() - j.started > 3600e3) this.jobs.delete(jid);
    Promise.resolve().then(() => work(job))
      .then((res) => Object.assign(job, { state: "done", result: res || null, progress: 1, phase: "Done." }))
      .catch((e) => { Object.assign(job, { state: "error", error: e.message }); job.log(e.message, "err"); })
      .finally(() => { job.finished = Date.now(); this.log(`fleet ${kind}: ${job.state}`); });
    return job.view();
  }
  job(jid) {
    const j = this.jobs.get(jid);
    if (!j) fail("No such job.");
    return j;
  }
}

// Quote a string for the shell, safely, when it has to go inside a script.
export const sq = (v) => `'${String(v ?? "").replace(/'/g, `'\\''`)}'`;

// ssh's own complaints, said plainly.
function sshWhy(err) {
  const e = String(err || "");
  if (/Permission denied/i.test(e)) return "the machine refused the key. Run the link command on it again.";
  if (/Connection refused/i.test(e)) return "nothing is listening on that port (is the SSH server running?).";
  if (/No route to host|Network is unreachable/i.test(e)) return "no route to that address from here.";
  if (/Name or service not known|could not resolve/i.test(e)) return "that name does not resolve from here.";
  if (/Connection timed out|Operation timed out/i.test(e)) return "it did not answer (a firewall, or it is off).";
  if (/HOST KEY|host key.*changed/i.test(e)) return "its host key changed since we linked it. Forget the machine and link it again.";
  if (/ENOENT|ssh.*not found/i.test(e)) return "this machine has no ssh client installed.";
  return null;
}

// Constant-time compare for the one-shot link token.
export function tokenEq(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}
