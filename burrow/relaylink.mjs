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
//              (signed the same way) when the link comes up and when it renews.

import { spawn, execFileSync } from "node:child_process";
import { createServer as netServer } from "node:net";
import { request as httpRequest } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { hostname } from "node:os";
import { isIP } from "node:net";
import { randomBytes, X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { sign, verify, VERSION as AGENT_VERSION } from "../relay/agent.mjs";

export { sign, verify, AGENT_VERSION };
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
  setup({ host, port = 22 }) {
    host = String(host || "").trim().toLowerCase();
    if (!isIP(host) && !HOST_RE.test(host)) throw new Error("The relay is your server's IP address or host name.");
    port = Number(port) || 22;
    if (!(port > 0 && port < 65536)) throw new Error("That isn't an SSH port.");
    this.ensureSshKey();
    if (!this.state.key || this.state.vps?.host !== host) this.state.key = randomBytes(32).toString("base64url");     // a new server, a new key
    this.state.token = { t: randomBytes(24).toString("base64url"), exp: Date.now() + TOKEN_MS, host, port };
    this.save();
    return { token: this.state.token.t, expires: this.state.token.exp, host, port };
  }
  tokenOk(t) { const k = this.state.token; return !!k && typeof t === "string" && t.length === k.t.length && t === k.t && Date.now() < k.exp; }
  // the install script for the VPS (the one-time link serves it)
  script(t, { suffix, base }) {
    if (!this.tokenOk(t)) return null;
    const pub = this.ensureSshKey(), S = this.state;
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
    this.save();
    this.log(`relay: ${host} registered (agent ${this.state.installed.version}, ${this.state.installed.mode})`);
    return { ok: true };
  }
  forget() {
    this.stop();
    this.state = { ...this.state, key: null, vps: null, installed: null, token: null };
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
  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    if (this.child) { try { this.child.kill("SIGTERM"); } catch { /* gone */ } this.child = null; }
    this.link = { state: "off", since: Date.now(), error: null };
  }
  running() { return !this.stopped; }

  // ------------------------------------------------------------ talking to the agent
  control(method, path, body) {
    return new Promise((resolve, reject) => {
      if (!this.localCtl || !this.configured()) return reject(new Error("no link"));
      const data = body ? JSON.stringify(body) : null;
      const r = httpRequest({ host: "127.0.0.1", port: this.localCtl, method, path, timeout: 10000,
        headers: { "x-aegis-relay": sign(this.keyBuf(), { host: "agent", ip: "-", method, url: path }), ...(data ? { "content-type": "application/json", "content-length": Buffer.byteLength(data) } : {}) } }, (res) => {
        let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => { try { const j = JSON.parse(b); res.statusCode < 400 ? resolve(j) : reject(new Error(j.error || `HTTP ${res.statusCode}`)); } catch { reject(new Error(`HTTP ${res.statusCode}`)); } });
      });
      r.on("timeout", () => r.destroy(new Error("timeout")));
      r.on("error", reject);
      r.end(data);
    });
  }
  // this machine's certificate to the agent, unless it already has that one
  async pushCert(cur) {
    if (!cur?.cert || !cur?.key || this.link.state !== "up") return null;
    const fp = new X509Certificate(cur.cert).fingerprint256;
    if (this.agent?.cert?.fingerprint === fp) return { same: true };
    const r = await this.control("POST", "/cert", { cert: cur.cert, key: cur.key });
    this.agent = { ...(this.agent || {}), cert: { fingerprint: r.fingerprint, notAfter: r.notAfter } };
    this.log(`relay: the certificate is on ${this.state.vps.host} (until ${new Date(r.notAfter).toISOString().slice(0, 10)})`);
    return r;
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
             agent: this.agent ? { version: this.agent.version, mode: this.agent.mode, cert: this.agent.cert, stats: this.agent.stats, at: this.agent.at } : null,
             pending: S.token ? { host: S.token.host, port: S.token.port, expires: S.token.exp } : null, agentVersion: AGENT_VERSION };
  }
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
[ "$(id -u)" = 0 ] || { echo "Run it as root (with sudo)." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "This needs a server with systemd." >&2; exit 1; }
say() { printf '  %s\\n' "$*"; }
echo; echo "  Aegis Relay"
# ---- Node.js 18+ (the agent's only need): the one here, or our own copy
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
MODE=tls; SITE=""; REPLACES=""
if ss -ltnp 2>/dev/null | grep -E '[:.]443 ' | grep -q caddy; then
  MODE=caddy
  if [ -d /etc/caddy/sites ] && grep -q 'sites/' /etc/caddy/Caddyfile 2>/dev/null; then SITE=/etc/caddy/sites/aegis-relay.caddy
  else SITE=/etc/aegis-relay/caddy.site; grep -qF "import $SITE" /etc/caddy/Caddyfile || printf '\\nimport %s\\n' "$SITE" >> /etc/caddy/Caddyfile; fi
  # an older hand-made site for the same names gives way when the agent's comes
  for f in /etc/caddy/sites/aegis-tunnels.caddy; do [ -f "$f" ] && grep -q ${q(`*${cfg.suffix}`)} "$f" && REPLACES="$f"; done
  say "Caddy is on :443: it keeps TLS, the agent sits behind it"
elif ss -ltn 2>/dev/null | grep -qE '[:.]443 '; then
  echo "Something other than Caddy already listens on :443; stop it, or put Caddy there." >&2; exit 1
else say "nothing on :443: the agent takes it"; fi
GID="$(getent group caddy | cut -d: -f3 || true)"
# ---- the agent
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
id aegis-relay >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/aegis-relay --shell /usr/sbin/nologin aegis-relay
install -d -m 700 -o aegis-relay -g aegis-relay /var/lib/aegis-relay/.ssh
printf '%s\\n' ${q(`restrict,port-forwarding,permitlisten="127.0.0.1:${remotePort}",permitopen="127.0.0.1:${controlPort}" ${pub}`)} > /var/lib/aegis-relay/.ssh/authorized_keys
chown aegis-relay:aegis-relay /var/lib/aegis-relay/.ssh/authorized_keys; chmod 600 /var/lib/aegis-relay/.ssh/authorized_keys
if sshd -T 2>/dev/null | grep -qiE '^allowtcpforwarding (no|local)$'; then
  echo "sshd forbids remote port forwarding (AllowTcpForwarding); allow it for aegis-relay:" >&2
  echo "  Match User aegis-relay" >&2; echo "    AllowTcpForwarding yes" >&2; exit 1
fi
# ---- the service
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
sleep 1; systemctl is-active --quiet aegis-relay-agent || { journalctl -u aegis-relay-agent -n 20 --no-pager >&2; exit 1; }
say "agent running ($MODE)"
# ---- tell your Aegis (and give it this server's SSH host key to pin)
HK="$(cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || cat /etc/ssh/ssh_host_ecdsa_key.pub)"
"$NODE" -e 'console.log(JSON.stringify({ hostKey: process.argv[1], version: process.argv[2], mode: process.argv[3] }))' "$HK" ${q(AGENT_VERSION)} "$MODE" \\
  | curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- ${q(`${base}/__gate/relay/register?t=${token}`)} >/dev/null
say "registered with your Aegis: it connects within a minute"
echo
`;
}
