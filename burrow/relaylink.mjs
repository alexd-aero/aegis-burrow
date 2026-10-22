// Aegis Relay: a server of yours (a VPS) carries the tunnels when this machine
// can't take them itself, and only you can use it.
//
//   setup      Settings → Domain (or POST /tunnels/relay/setup {host}) makes a key
//              for the relay, an SSH key for this machine, and a one-time link
//              (30 minutes): `curl -fsSL https://<dashboard>/__gate/relay/agent.sh?t=… | sudo bash`
//              on the VPS installs the agent (relay/agent.mjs) and a locked-down
//              user, aegis-relay, that this machine's key can use for exactly two
//              port forwards and nothing else; then the VPS registers back
//              (its SSH host key is pinned from then on).
//   the link   while the tunnels actually go through the relay (and only then):
//              ssh -N -R VPS:127.0.0.1:18452 -> here 127.0.0.1:4302 (the relay
//              listener) and -L here -> VPS:127.0.0.1:18451 (the agent's control).
//              The SSH transport is post-quantum (sntrup761x25519) where the
//              server has it.
//   requests   every relayed request carries x-aegis-relay: an HMAC-SHA256 over
//              a timestamp, a one-time nonce, the host, the visitor's address, the
//              method and the path, with the key only the agent and this machine
//              hold. The relay listener refuses anything else: nothing else on
//              the VPS can feed requests here or claim another visitor's address.
//   the cert   this machine's Let's Encrypt wildcard is pushed to the agent
//              (signed the same way) when the link comes up and when it renews;
//              so is each other domain's (domains.mjs, route "vps"), with its suffix.
//   the edge   public tunnels are checked on the VPS first (agent 1.2+): which
//              names are public and which addresses may pass (a scan cleared
//              them, or they're yours) or not (banned) is mirrored there, in
//              full once and then what changed; someone new gets a "checking"
//              page there while the agent asks this machine to scan them
//   machines   the VPS is linked into Machines too (agent 1.4+, POST /fleet/link):
//              the gate hands the agent the usual link script and it runs it as
//              root, once; forgetting it in Machines keeps it out (state.machine).
//   updates    an agent older than this Aegis's (relay/agent.mjs) is sent the
//              new one over the link (1.1 and later take it by themselves; 1.0
//              needs the install command once more).

import { spawn, execFileSync } from "node:child_process";
import { createServer as netServer } from "node:net";
import { request as httpRequest } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { hostname } from "node:os";
import { isIP } from "node:net";
import { randomBytes, X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { sign, verify, visitorPage, VERSION as AGENT_VERSION } from "../relay/agent.mjs";

export { sign, verify, visitorPage, AGENT_VERSION };
const newer = (a, b) => { const x = String(a).split(".").map(Number), y = String(b).split(".").map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); return false; };
const AGENT_FILE = join(dirname(fileURLToPath(import.meta.url)), "..", "relay", "agent.mjs");
const TOKEN_MS = 30 * 60e3;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const freePort = () => new Promise((res, rej) => { const s = netServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); s.on("error", rej); });

export class RelayLink {
  constructor({ dataDir, log, sshBin = "ssh" }) {
    this.dir = join(dataDir, "relay");
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    this.file = join(this.dir, "link.json");
    this.keyFile = join(this.dir, "id_ed25519");
    this.knownHosts = join(this.dir, "known_hosts");
    this.log = log || console.log;
    this.sshBin = sshBin;
    this.state = { key: null, vps: null, installed: null, token: null, remotePort: 18452, controlPort: 18451, httpPort: 18450 };
    try { this.state = { ...this.state, ...JSON.parse(readFileSync(this.file, "utf8")) }; } catch { /* first time */ }
    this.child = null; this.link = { state: "off", since: null, error: null }; this.agent = null;
    this.checked = null;                // the last check that this machine reaches the agent: {ok, at, error}
    this.verifying = false;
    this.localCtl = null; this.stopped = true; this.backoff = 5000; this.timer = null;
    this.onUp = null;                   // the link came up (push the certificate)
  }
  save() {
    writeFileSync(this.file + ".tmp", JSON.stringify(this.state, null, 1), { mode: 0o600 });
    renameSync(this.file + ".tmp", this.file);
  }
  configured() { return !!(this.state.installed && this.state.vps && this.state.key); }
  keyBuf() { return Buffer.from(this.state.key, "base64url"); }
  ensureSshKey() {
    if (!existsSync(this.keyFile)) {
      execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", `aegis-relay@${hostname()}`, "-f", this.keyFile], { stdio: "ignore" });
      chmodSync(this.keyFile, 0o600);
    }
    return readFileSync(this.keyFile + ".pub", "utf8").trim();
  }

  // ------------------------------------------------------------ setup
  setup({ host, port = 22, suffix }) {
    host = String(host || "").trim().toLowerCase();
    if (!isIP(host) && !HOST_RE.test(host)) throw new Error("The relay is your server's IP address or host name.");
    port = Number(port) || 22;
    if (!(port > 0 && port < 65536)) throw new Error("That isn't an SSH port.");
    this.ensureSshKey();
    if (!this.state.key || this.state.vps?.host !== host) this.state.key = randomBytes(32).toString("base64url");     // a new server, a new key
    if (!/^\.[a-z0-9.-]+$/.test(String(suffix || ""))) throw new Error("No tunnel names for the relay to carry yet.");
    this.state.token = { t: randomBytes(24).toString("base64url"), exp: Date.now() + TOKEN_MS, host, port, suffix };
    this.checked = null;
    this.save();
    return { token: this.state.token.t, expires: this.state.token.exp, host, port };
  }
  tokenOk(t) { const k = this.state.token; return !!k && typeof t === "string" && t.length === k.t.length && t === k.t && Date.now() < k.exp; }
  // the install script for the VPS (the one-time link serves it)
  script(t, { base }) {
    if (!this.tokenOk(t)) return null;
    const pub = this.ensureSshKey(), S = this.state, suffix = S.token.suffix;
    const agent = readFileSync(AGENT_FILE, "utf8");
    const cfg = { key: S.key, suffix, upstreamPort: S.remotePort, controlPort: S.controlPort, httpPort: S.httpPort, certDir: "/etc/aegis-relay/certs" };
    return installScript({ cfg, pub, agent, base, token: t, remotePort: S.remotePort, controlPort: S.controlPort });
  }
  register(t, { hostKey, version, mode } = {}) {
    if (!this.tokenOk(t)) throw new Error("That setup link has expired: make a new one in Settings → Domain.");
    const hk = String(hostKey || "").trim().split(/\s+/);
    if (!/^(ssh-ed25519|ecdsa-sha2-nistp\d+|ssh-rsa)$/.test(hk[0] || "") || !/^[A-Za-z0-9+/=]{40,}$/.test(hk[1] || "")) throw new Error("The server didn't send an SSH host key.");
    const { host, port } = this.state.token;
    const name = port === 22 ? host : `[${host}]:${port}`;
    writeFileSync(this.knownHosts, `${name} ${hk[0]} ${hk[1]}\n`, { mode: 0o600 });
    this.state.vps = { host, port };
    this.state.installed = { at: Date.now(), version: String(version || "").slice(0, 20), mode: mode === "tls" ? "tls" : "caddy", hostKey: `${hk[0]} ${hk[1].slice(0, 16)}…` };
    this.state.token = null;
    this.state.machine = null;                // set up again: it may join Machines again
    this.save();
    this.log(`relay: ${host} registered (agent ${this.state.installed.version}, ${this.state.installed.mode})`);
    return { ok: true };
  }
  forget() {
    this.stop();
    this.state = { ...this.state, key: null, vps: null, installed: null, token: null, machine: null };
    try { writeFileSync(this.knownHosts, ""); } catch { /* none */ }
    this.save();
  }

  // ------------------------------------------------------------ the link (only while it's used)
  async start(listenPort) {
    if (!this.configured() || (this.child && !this.stopped)) return;
    this.stopped = false;
    this.listenPort = listenPort;
    this.localCtl = await freePort();
    this.spawn();
  }
  spawn() {
    if (this.stopped) return;
    const { vps, remotePort, controlPort } = this.state;
    const args = ["-N", "-T", "-i", this.keyFile, "-p", String(vps.port),
      "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
      "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=15",
      "-o", `UserKnownHostsFile=${this.knownHosts}`, "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", "KexAlgorithms=sntrup761x25519-sha512@openssh.com,curve25519-sha256",
      "-R", `127.0.0.1:${remotePort}:127.0.0.1:${this.listenPort}`, "-L", `127.0.0.1:${this.localCtl}:127.0.0.1:${controlPort}`,
      `aegis-relay@${vps.host}`];
    const child = spawn(this.sshBin, args, { stdio: ["ignore", "ignore", "pipe"] });
    this.child = child;
    this.link = { state: "connecting", since: Date.now(), error: null };
    let err = "";
    child.stderr.on("data", (d) => { err = (err + d).slice(-600); });
    // up once the agent answers through it
    const check = async (n) => {
      if (this.child !== child || this.stopped) return;
      const s = await this.control("GET", "/status").catch(() => null);
      if (s?.version) {
        this.agent = { ...s, at: Date.now() };
        if (this.link.state !== "up") { this.link = { state: "up", since: Date.now(), error: null }; this.backoff = 5000; this.log(`relay: linked with ${vps.host} (agent ${s.version})`); this.onUp?.(); }
        return;
      }
      if (n < 20) setTimeout(() => check(n + 1), 1500).unref?.();
    };
    setTimeout(() => check(0), 1500).unref?.();
    child.on("exit", (code) => {
      if (this.child !== child) return;
      this.child = null;
      const why = (err.trim().split("\n").filter((l) => !/^Warning: Permanently added/.test(l)).pop() || `ssh exited (${code})`).slice(0, 200);
      this.link = { state: this.stopped ? "off" : "down", since: Date.now(), error: this.stopped ? null : why };
      if (this.stopped) return;
      this.log(`relay: the link to ${vps.host} dropped: ${why}; again in ${Math.round(this.backoff / 1000)}s`);
      this.timer = setTimeout(() => this.spawn(), this.backoff);
      this.backoff = Math.min(60000, this.backoff * 2);
    });
  }
  // Is the agent really reachable? Starts the link if it isn't running and waits
  // for the agent to answer through it. (The caller decides whether it stays up.)
  async verify(listenPort, ms = 30000) {
    if (!this.configured()) return (this.checked = { ok: false, at: Date.now(), error: "no relay agent is registered" });
    this.verifying = true;
    try {
      if (this.stopped || !this.child) { this.stop(); await this.start(listenPort); }
      const until = Date.now() + ms;
      while (Date.now() < until && this.link.state !== "up") await new Promise((r) => setTimeout(r, 400));
      const ok = this.link.state === "up";
      // what the agent is now (it may have been updated or reinstalled since the link came up)
      if (ok) { const st = await this.control("GET", "/status").catch(() => null); if (st?.version) this.agent = { ...st, at: Date.now() }; }
      this.checked = { ok, at: Date.now(), error: ok ? null : explain(this.link.error) || "the agent didn't answer through the link" };
      if (ok) this.log(`relay: checked: this machine reaches the agent on ${this.state.vps.host}`);
      else this.log(`relay: check failed for ${this.state.vps.host}: ${this.checked.error}`);
      return this.checked;
    } finally { this.verifying = false; }
  }
  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    if (this.child) { try { this.child.kill("SIGTERM"); } catch { /* gone */ } this.child = null; }
    this.link = { state: "off", since: Date.now(), error: null };
  }
  running() { return !this.stopped; }

  // ------------------------------------------------------------ talking to the agent
  control(method, path, body, timeout = 10000) {
    return new Promise((resolve, reject) => {
      if (!this.localCtl || !this.configured()) return reject(new Error("no link"));
      const data = body ? JSON.stringify(body) : null;
      const r = httpRequest({ host: "127.0.0.1", port: this.localCtl, method, path, timeout,
        headers: { "x-aegis-relay": sign(this.keyBuf(), { host: "agent", ip: "-", method, url: path }), ...(data ? { "content-type": "application/json", "content-length": Buffer.byteLength(data) } : {}) } }, (res) => {
        let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => { try { const j = JSON.parse(b); res.statusCode < 400 ? resolve(j) : reject(new Error(j.error || `HTTP ${res.statusCode}`)); } catch { reject(new Error(`HTTP ${res.statusCode}`)); } });
      });
      r.on("timeout", () => r.destroy(new Error("timeout")));
      r.on("error", reject);
      r.end(data);
    });
  }
  // a certificate to the agent, unless it already has that one: the tunnels'
  // wildcard (no suffix), or another domain's (suffix ".example.org")
  async pushCert(cur, suffix) {
    if (!cur?.cert || !cur?.key || this.link.state !== "up") return null;
    const fp = new X509Certificate(cur.cert).fingerprint256;
    const has = suffix ? this.agent?.zones?.find((z) => z.suffix === suffix)?.cert : this.agent?.cert;
    if (has?.fingerprint === fp && !cur.force) return { same: true };
    if (suffix && !this.can("zones")) throw new Error(`the agent on ${this.state.vps.host} is ${this.agent?.version || "too old"}: it needs ${AGENT_VERSION} for more domains`);
    const r = await this.control("POST", "/cert", { cert: cur.cert, key: cur.key, ...(suffix ? { suffix } : {}) });
    const info = { fingerprint: r.fingerprint, notAfter: r.notAfter };
    if (suffix) {
      const zones = (this.agent?.zones || []).filter((z) => z.suffix !== suffix);
      this.agent = { ...(this.agent || {}), zones: [...zones, { suffix, cert: info }] };
    } else this.agent = { ...(this.agent || {}), cert: info };
    this.log(`relay: the certificate for *${suffix || this.agent?.suffix || ""} is on ${this.state.vps.host} (until ${new Date(r.notAfter).toISOString().slice(0, 10)})`);
    return r;
  }
  async removeZone(suffix) {
    if (this.link.state !== "up" || !this.can("zones")) return null;
    const r = await this.control("POST", "/zones/remove", { suffix });
    if (this.agent?.zones) this.agent.zones = this.agent.zones.filter((z) => z.suffix !== suffix);
    return r;
  }
  // who may pass, to the agent: {on, hosts, cleared, banned}; only what changed when it can
  async syncEdge(want) {
    if (this.link.state !== "up" || !this.can("edge")) return null;
    const S = this.edgeSent, agentEpoch = this.agent?.edge?.epoch;
    const full = async () => {
      const epoch = randomBytes(6).toString("base64url");
      const r = await this.control("POST", "/edge", { full: true, epoch, ...want });
      this.edgeSent = { epoch, on: want.on, hosts: want.hosts.join(","), cleared: new Set(want.cleared), banned: new Set(want.banned) };
      this.agent = { ...(this.agent || {}), edge: { ...r } };
      return r;
    };
    if (!S || !agentEpoch || agentEpoch !== S.epoch) return full();
    const nowC = new Set(want.cleared), nowB = new Set(want.banned);
    const c = { add: want.cleared.filter((x) => !S.cleared.has(x)), del: [...S.cleared].filter((x) => !nowC.has(x)) };
    const b = { add: want.banned.filter((x) => !S.banned.has(x)), del: [...S.banned].filter((x) => !nowB.has(x)) };
    const hosts = want.hosts.join(",");
    if (!c.add.length && !c.del.length && !b.add.length && !b.del.length && hosts === S.hosts && want.on === S.on) return { same: true };
    try {
      const r = await this.control("POST", "/edge", { epoch: S.epoch, on: want.on, ...(hosts !== S.hosts ? { hosts: want.hosts } : {}),
        add: { cleared: c.add, banned: b.add }, del: { cleared: c.del, banned: b.del } });
      this.edgeSent = { ...S, on: want.on, hosts, cleared: nowC, banned: nowB };
      this.agent = { ...(this.agent || {}), edge: { ...r } };
      return r;
    } catch (e) { if (/full/.test(e.message)) return full(); throw e; }
  }
  // the VPS into Machines: its agent runs the link script as root (-> {ok, code, out})
  async linkMachine(script) {
    if (this.link.state !== "up" || !this.can("fleet")) throw new Error(`the agent on ${this.state.vps?.host} is ${this.agent?.version || "not linked"}: it needs 1.4 for this`);
    return this.control("POST", "/fleet/link", { script }, 300000);
  }
  // what became of it in Machines, for this VPS only: {host, id} | {host, declined} | {host, failedAt, error}
  machine() { const m = this.state.machine; return m && m.host === this.state.vps?.host ? m : null; }
  setMachine(m) { this.state.machine = m ? { host: this.state.vps?.host, ...m } : null; this.save(); }
  can(feature) { return !!this.agent?.features?.includes(feature); }
  // what the agent is missing: null, "update" (it takes one), or "reinstall" (1.0: the command once more)
  outdated() {
    if (!this.agent?.version || !newer(AGENT_VERSION, this.agent.version)) return null;
    return this.can("update") ? "update" : "reinstall";
  }
  // send this Aegis's agent; it restarts, and the link sees it come back
  async updateAgent() {
    if (this.link.state !== "up" || this.outdated() !== "update") return null;
    const from = this.agent.version;
    const r = await this.control("POST", "/update", { code: readFileSync(AGENT_FILE, "utf8"), version: AGENT_VERSION });
    this.log(`relay: updating the agent on ${this.state.vps.host} from ${from} to ${AGENT_VERSION}`);
    for (let i = 0; i < 30; i++) {
      await new Promise((res) => setTimeout(res, 1000));
      const s = await this.control("GET", "/status").catch(() => null);
      if (s?.version === AGENT_VERSION) { this.agent = { ...s, at: Date.now() }; this.log(`relay: the agent on ${this.state.vps.host} is ${AGENT_VERSION}`); return r; }
    }
    throw new Error(`the agent on ${this.state.vps.host} didn't come back as ${AGENT_VERSION}`);
  }

  // ------------------------------------------------------------ a request through the relay
  // -> the visitor's address, or null (refused)
  verifyRequest(req, host) {
    if (!this.configured()) return null;
    const ip = String(req.headers["x-aegis-relay-ip"] || "");
    if (!isIP(ip)) return null;
    return verify(this.keyBuf(), req.headers["x-aegis-relay"], { host, ip, method: req.method, url: req.url }) ? ip : null;
  }

  view() {
    const S = this.state;
    return { configured: this.configured(), vps: S.vps, installed: S.installed, link: this.link,
             agent: this.agent ? { version: this.agent.version, mode: this.agent.mode, cert: this.agent.cert, zones: this.agent.zones || null, features: this.agent.features || [],
                                   stats: this.agent.stats, at: this.agent.at, outdated: this.outdated() } : null,
             pending: S.token ? { host: S.token.host, port: S.token.port, expires: S.token.exp } : null, agentVersion: AGENT_VERSION,
             checked: this.checked, machine: this.machine() };
  }
}

// What an ssh error means, for someone who just ran the installer.
function explain(err) {
  const e = String(err || "");
  if (!e) return null;
  if (/Permission denied/i.test(e)) return `the server refused this machine's key (${e}): run the install command again`;
  if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(e)) return "the server's SSH host key changed since it registered: run the install command again if you reinstalled it";
  if (/Connection refused/i.test(e)) return "nothing answers on its SSH port (is sshd running, on port 22?)";
  if (/timed out|No route to host|Network is unreachable/i.test(e)) return `its SSH port doesn't answer (${e}): a firewall in front of the server?`;
  if (/remote port forwarding failed|forwarding failed/i.test(e)) return "the server refused the port forward (sshd's AllowTcpForwarding, or another program holds the port)";
  return e;
}

// ------------------------------------------------------------------ the install script
function installScript({ cfg, pub, agent, base, token, remotePort, controlPort }) {
  const q = (s) => `'${String(s).replace(/'/g, `'"'"'`)}'`;
  return `#!/usr/bin/env bash
# Aegis Relay agent installer, made for one server by your Aegis (${base}).
# What it does: a locked-down user "aegis-relay" that only your Aegis's key can
# use, for two port forwards (127.0.0.1:${remotePort} in, 127.0.0.1:${controlPort} out)
# and nothing else; the agent (/opt/aegis-relay/agent.mjs) as aegis-relay-agent.service;
# then it tells your Aegis it's done (and this server's SSH host key, which Aegis pins).
set -euo pipefail
say() { printf '  %s\\n' "$*"; }
die() { trap - EXIT; printf '\\n  \\033[31m✗ %s\\033[0m\\n\\n' "$*" >&2; exit 1; }
STEP="starting"
trap 'rc=$?; [ $rc -ne 0 ] && printf "\\n  \\033[31m✗ setup stopped while %s (exit %s). Nothing on your Aegis changed; fix that and paste the command again (make a new one in Settings → Domain if 30 minutes have passed).\\033[0m\\n\\n" "$STEP" "$rc" >&2' EXIT
[ "$(id -u)" = 0 ] || die "Run it as root (with sudo)."
command -v systemctl >/dev/null || die "This needs a Linux server with systemd."
for c in curl ss tar; do command -v $c >/dev/null || die "This needs $c (install it, then paste the command again)."; done
echo; echo "  Aegis Relay"
# ---- Node.js 18+ (the agent's only need): the one here, or our own copy
STEP="getting Node.js"
NODE=""
for n in "$(command -v node 2>/dev/null)" /usr/local/bin/node /opt/aegis-relay/node/bin/node; do
  [ -n "$n" ] && [ -x "$n" ] && "$n" -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' 2>/dev/null && { NODE="$n"; break; }
done
if [ -z "$NODE" ]; then
  case "$(uname -m)" in x86_64) A=x64;; aarch64|arm64) A=arm64;; armv7l) A=armv7l;; *) echo "No Node.js for $(uname -m)" >&2; exit 1;; esac
  V=v22.12.0
  say "getting Node.js $V ($A)…"
  mkdir -p /opt/aegis-relay/node
  curl -fsSL "https://nodejs.org/dist/$V/node-$V-linux-$A.tar.xz" | tar -xJ -C /opt/aegis-relay/node --strip-components=1
  NODE=/opt/aegis-relay/node/bin/node
fi
say "Node.js $("$NODE" -v) at $NODE"
# ---- where visitors arrive: Caddy already on :443 (it terminates TLS), or the agent itself
STEP="looking at port 443"
MODE=tls; SITE=""; REPLACES=""
if ss -ltnp 2>/dev/null | grep -E '[:.]443 ' | grep -q caddy; then
  MODE=caddy
  # the agent writes its site there with the first certificate, imports it in the
  # Caddyfile (or takes over an older site's import line), and checks with caddy validate
  if [ -d /etc/caddy/sites ]; then SITE=/etc/caddy/sites/aegis-relay.caddy; else SITE=/etc/aegis-relay/caddy.site; fi
  # an older hand-made site for the same names gives way when the agent's comes
  for f in /etc/caddy/sites/aegis-tunnels.caddy; do [ -f "$f" ] && grep -q ${q(`*${cfg.suffix}`)} "$f" && REPLACES="$f"; done
  say "Caddy is on :443: it keeps TLS, the agent sits behind it"
elif ss -ltn 2>/dev/null | grep -qE '[:.]443 '; then
  die "Something other than Caddy already listens on :443 ($(ss -ltnp 2>/dev/null | grep -E '[:.]443 ' | grep -o 'users:(("[^"]*' | head -1 | cut -d'"' -f2)); stop it, or put Caddy there."
else say "nothing on :443: the agent takes it"; fi
GID="$(getent group caddy | cut -d: -f3 || true)"
# ---- the firewall: visitors need 443 in (and 80 for nothing but redirects); this machine's SSH needs 22
STEP="checking the firewall"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw status | grep -qE '^(443|443/tcp|80,443/tcp|Nginx Full|WWW Full|Caddy)\\b.*ALLOW' || { say "ufw is on and doesn't allow 443: allowing it"; ufw allow 443/tcp >/dev/null; }
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --list-services 2>/dev/null | grep -qw https || firewall-cmd --list-ports 2>/dev/null | grep -qw 443/tcp || { say "firewalld doesn't allow 443: allowing it"; firewall-cmd -q --permanent --add-service=https && firewall-cmd -q --reload; }
fi
# ---- the agent
STEP="installing the agent"
mkdir -p /opt/aegis-relay /etc/aegis-relay/certs; chmod 750 /etc/aegis-relay /etc/aegis-relay/certs
[ -n "$GID" ] && chgrp "$GID" /etc/aegis-relay /etc/aegis-relay/certs
cat > /opt/aegis-relay/agent.mjs <<'AEGIS_RELAY_AGENT'
${agent}
AEGIS_RELAY_AGENT
umask 077
"$NODE" -e '
  const c = JSON.parse(process.argv[1]);
  Object.assign(c, { mode: process.argv[2], caddySite: process.argv[3] || undefined, replaces: process.argv[4] || undefined,
                     caddyGroup: process.argv[5] ? Number(process.argv[5]) : undefined, tlsPort: 443 });
  require("fs").writeFileSync("/etc/aegis-relay/config.json", JSON.stringify(c, null, 1));' ${q(JSON.stringify(cfg))} "$MODE" "$SITE" "$REPLACES" "$GID"
umask 022
# ---- the user only your Aegis can use, and only for its two forwards
STEP="making the aegis-relay user"
id aegis-relay >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/aegis-relay --shell /usr/sbin/nologin aegis-relay
install -d -m 700 -o aegis-relay -g aegis-relay /var/lib/aegis-relay/.ssh
printf '%s\\n' ${q(`restrict,port-forwarding,permitlisten="127.0.0.1:${remotePort}",permitopen="127.0.0.1:${controlPort}" ${pub}`)} > /var/lib/aegis-relay/.ssh/authorized_keys
chown aegis-relay:aegis-relay /var/lib/aegis-relay/.ssh/authorized_keys; chmod 600 /var/lib/aegis-relay/.ssh/authorized_keys
if sshd -T 2>/dev/null | grep -qiE '^allowtcpforwarding (no|local)$'; then
  die "sshd forbids remote port forwarding (AllowTcpForwarding). Add this to /etc/ssh/sshd_config, run systemctl reload ssh, and paste the command again:
      Match User aegis-relay
        AllowTcpForwarding yes"
fi
if sshd -T 2>/dev/null | grep -qiE '^allowusers ' && ! sshd -T 2>/dev/null | grep -iE '^allowusers ' | grep -qw aegis-relay; then
  die "sshd only lets some users in (AllowUsers). Add aegis-relay to that line in /etc/ssh/sshd_config, run systemctl reload ssh, and paste the command again."
fi
# ---- the service
STEP="starting the agent"
cat > /etc/systemd/system/aegis-relay-agent.service <<UNIT
[Unit]
Description=Aegis Relay agent: carries your tunnels to your Aegis, signed
After=network-online.target

[Service]
ExecStart=$NODE /opt/aegis-relay/agent.mjs
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable aegis-relay-agent >/dev/null 2>&1
systemctl restart aegis-relay-agent
sleep 2; systemctl is-active --quiet aegis-relay-agent || { journalctl -u aegis-relay-agent -n 20 --no-pager >&2; die "The agent didn't start (its log is above)."; }
say "agent running ($MODE)"
# ---- tell your Aegis (and give it this server's SSH host key to pin); it then
# connects over SSH as aegis-relay and answers with whether that worked
STEP="registering with your Aegis"
HK="$(cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || cat /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null || true)"
[ -n "$HK" ] || die "This server has no ed25519 or ECDSA SSH host key for your Aegis to pin."
say "registering, and waiting for your Aegis to connect back (up to a minute)…"
OUT="$("$NODE" -e 'console.log(JSON.stringify({ hostKey: process.argv[1], version: process.argv[2], mode: process.argv[3] }))' "$HK" ${q(AGENT_VERSION)} "$MODE" \\
  | curl -sS --max-time 90 -w '\\n%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @- ${q(`${base}/__gate/relay/register?t=${token}`)} 2>&1)" || die "Couldn't reach your Aegis at ${base}: $OUT"
CODE="$(printf '%s' "$OUT" | tail -n1)"; BODY="$(printf '%s' "$OUT" | sed '$d')"
field() { printf '%s' "$BODY" | "$NODE" -e 'let b="";process.stdin.on("data",d=>b+=d).on("end",()=>{try{const v=JSON.parse(b)[process.argv[1]];console.log(v==null?"":String(v))}catch{console.log("")}})' "$1"; }
[ "$CODE" = 200 ] || die "Your Aegis said no: $(field error || echo "HTTP $CODE")"
if [ "$(field linked)" = "true" ]; then
  trap - EXIT
  echo; printf '  \\033[32m✓ Linked.\\033[0m Your Aegis reached this server over SSH and the agent answered.\\n'
  say 'Back in Settings → Domain, "Move every tunnel to the VPS" is ready.'
  say 'This server also shows up in Burrow → Machines in a minute (its specs, apps, a terminal).'
  echo
else
  STEP="checking the link"
  die "Registered, but your Aegis couldn't connect back: $(field error). It keeps trying; Settings → Domain shows the same."
fi
`;
}
