// Burrow, the engine: linking a domain, running the connector, and quick tunnels.
//
// Linking a domain (Settings → Domain) is three steps, all from the browser:
//
//   1. login   `cloudflared tunnel login` prints an authorization link. The
//              dashboard shows it as a button; the user opens it, picks one of
//              their zones, and cloudflared receives a cert.pem for that zone.
//              It runs with HOME=data/cf/home, so it never touches (or trips
//              over) a ~/.cloudflared/cert.pem the user already has.
//   2. link    the user picks a name (default "aegis"). Aegis creates a named
//              tunnel, points <name>.<zone> at it (a proxied CNAME, through the
//              API token inside cert.pem), and writes a cloudflared config whose
//              ingress sends <name>.<zone> and *.<zone> to the dashboard (Aegis).
//   3. run     Aegis runs that cloudflared itself (--post-quantum) and
//              restarts it if it exits.
//
// Tunnels then live at tunnel-PORT-<name>.<zone> (tunnels.mjs adds a record
// per tunnel). Unlinking removes every record, the tunnel and the files.
//
// A domain can also be "external" (managed: false): an existing cloudflared
// service already routes it here, and Aegis only manages DNS records.
//
// No domain? QuickTunnels gives each tunnel its own `cloudflared tunnel --url`
// on a random *.trycloudflare.com name. No account needed, but the names change
// whenever the connector restarts.

import { spawn, execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync, accessSync, constants } from "node:fs";
import { join, delimiter } from "node:path";
import { randomBytes } from "node:crypto";

const LOGIN_URL_RE = /https:\/\/dash\.cloudflare\.com\/argotunnel\?[^\s"']+/;
const QUICK_URL_RE = /https:\/\/([a-z0-9-]+\.trycloudflare\.com)/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

export function findCloudflared(configured, home) {
  const candidates = [configured, home && join(home, "bin", "cloudflared"),
    ...String(process.env.PATH || "").split(delimiter).map((d) => d && join(d, "cloudflared")),
    "/usr/local/bin/cloudflared", "/usr/bin/cloudflared"].filter(Boolean);
  for (const c of candidates) {
    try { accessSync(c, constants.X_OK); return c; } catch { /* next */ }
  }
  return null;
}

function run(bin, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 60000, maxBuffer: 4 << 20, ...opts }, (err, stdout, stderr) =>
      resolve({ code: err ? (err.code ?? 1) : 0, out: String(stdout || ""), err: String(stderr || err?.message || "") }));
  });
}

export function decodeCert(path) {
  const pem = readFileSync(path, "utf8");
  const m = /-----BEGIN [A-Z ]+-----\s*([\s\S]+?)\s*-----END/.exec(pem);
  if (!m) throw new Error("That cert.pem has no Argo Tunnel token in it.");
  const d = JSON.parse(Buffer.from(m[1].replace(/\s+/g, ""), "base64").toString("utf8"));
  if (!d.zoneID || !d.apiToken) throw new Error("That cert.pem has no zone or API token in it.");
  return { zoneId: d.zoneID, accountId: d.accountID, token: d.apiToken };
}

async function cfApi(token, method, path, body) {
  const r = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15000),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.success) throw new Error((j.errors || []).map((e) => e.message).join("; ") || `Cloudflare said HTTP ${r.status}`);
  return j.result;
}

// ---------------------------------------------------------------- supervisor
// Keeps one cloudflared process alive: restarts it with backoff, keeps the
// last lines of its log for the dashboard.
class Supervised {
  constructor(name, log) { this.name = name; this.log = log; this.proc = null; this.lines = []; this.want = false; this.restarts = 0; }
  start(bin, args, env, onLine) {
    this.want = true;
    this.bin = bin; this.args = args; this.env = env; this.onLine = onLine;
    this.spawn();
  }
  spawn() {
    if (!this.want || this.proc) return;
    const p = spawn(this.bin, this.args, { env: { ...process.env, ...this.env }, stdio: ["ignore", "pipe", "pipe"] });
    this.proc = p; this.since = Date.now();
    const feed = (buf) => {
      for (const line of String(buf).split("\n")) {
        if (!line.trim()) continue;
        this.lines.push(line.slice(0, 400));
        if (this.lines.length > 60) this.lines.shift();
        this.onLine?.(line);
      }
    };
    p.stdout.on("data", feed);
    p.stderr.on("data", feed);
    p.on("error", (e) => { this.lines.push(`could not start ${this.bin}: ${e.message}`); });
    p.on("exit", (code) => {
      this.proc = null;
      if (!this.want) return;
      this.restarts++;
      const wait = Math.min(60000, 2000 * 2 ** Math.min(5, this.restarts - 1));
      this.log(`${this.name}: cloudflared exited (${code}); restarting in ${wait / 1000}s`);
      this.timer = setTimeout(() => this.spawn(), wait);
      // a run that lasted a while resets the backoff
      if (Date.now() - this.since > 120000) this.restarts = 0;
    });
  }
  stop() {
    this.want = false;
    clearTimeout(this.timer);
    if (this.proc) { try { this.proc.kill("SIGTERM"); } catch { /* gone */ } }
    this.proc = null;
  }
  get running() { return !!this.proc; }
}

// ---------------------------------------------------------------- quick tunnels
export class QuickTunnels {
  constructor({ bin, origin, log, dataDir }) {
    this.bin = bin;           // () => path or null
    this.origin = origin;     // () => { url, insecure }
    this.log = log;
    this.tunnels = new Map(); // port -> { sup, host, error }
    // cloudflared reads ~/.cloudflared/config.yml (or /etc/cloudflared/...)
    // when no --config is given, and a quick tunnel then follows *that*
    // file's ingress rules, which usually end in http_status:404. An empty
    // config of our own (and a HOME of our own) keeps quick tunnels clean.
    this.home = join(dataDir, "cf", "quick-home");
    this.config = join(dataDir, "cf", "quick.yml");
    mkdirSync(this.home, { recursive: true, mode: 0o700 });
    writeFileSync(this.config, "# Aegis quick tunnels: no ingress here, --url decides.\n", { mode: 0o600 });
  }
  start(port) {
    if (this.tunnels.has(port)) return;
    const bin = this.bin();
    const q = { sup: new Supervised(`quick ${port}`, this.log), host: null, error: null };
    this.tunnels.set(port, q);
    if (!bin) { q.error = "cloudflared is not installed"; return; }
    const o = this.origin();
    const args = ["tunnel", "--no-autoupdate", "--config", this.config, "--url", o.url];
    if (o.insecure) args.push("--no-tls-verify");
    q.sup.start(bin, args, { HOME: this.home }, (line) => {
      const m = QUICK_URL_RE.exec(line);
      if (m) { q.host = m[1].toLowerCase(); q.error = null; this.log(`quick tunnel for ${port}: https://${q.host}`); }
      else if (/failed to request quick Tunnel|429 Too Many Requests/i.test(line)) q.error = line.replace(/^\S+\s+\S+\s+/, "").slice(0, 200);
    });
  }
  stop(port) {
    const q = this.tunnels.get(port);
    if (q) { q.sup.stop(); this.tunnels.delete(port); }
  }
  stopAll() { for (const port of [...this.tunnels.keys()]) this.stop(port); }
  host(port) { return this.tunnels.get(port)?.host || null; }
  portOf(host) {
    for (const [port, q] of this.tunnels) if (q.host && q.host === host) return port;
    return null;
  }
  status(port) {
    const q = this.tunnels.get(port);
    if (!q) return { state: "off" };
    if (q.host && q.sup.running) return { state: "up" };
    if (q.error) return { state: "error", error: q.error };
    return { state: "starting" };
  }
}

// ---------------------------------------------------------------- domain
export class Cloudflare {
  constructor({ settings, dataDir, home, origin, log, onDomain }) {
    this.settings = settings;
    this.appHome = home;                           // where a private cloudflared may live (HOME/bin)
    this.dir = join(dataDir, "cf");
    this.home = join(this.dir, "home");          // HOME for `cloudflared tunnel login`
    this.origin = origin;                          // () => { url, insecure, caPool }
    this.log = log;
    this.onDomain = onDomain;                      // async (domain|null, phase) => void
    this.login = null;                             // { proc, url, started, error }
    this.connector = new Supervised("connector", log);
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const d = this.domain();
    if (d?.managed) this.startConnector();
  }

  bin() { return findCloudflared(this.settings.get("cloudflared"), this.appHome); }
  domain() { return this.settings.get("domain"); }
  certPath() { return join(this.dir, "cert.pem"); }

  async zoneOfCert() {
    const c = decodeCert(this.certPath());
    let name = null;
    try { name = (await cfApi(c.token, "GET", `/zones/${c.zoneId}`)).name; } catch (e) { this.log("cf: zone lookup failed", e.message); }
    return { id: c.zoneId, name };
  }

  state() {
    const d = this.domain();
    const out = {
      cloudflared: !!this.bin(),
      domain: d ? { mainHost: d.mainHost, zone: d.zone?.name || d.mainHost.split(".").slice(1).join("."), managed: !!d.managed,
                    tunnelId: d.tunnelId, label: d.mainHost.split(".")[0] } : null,
      connector: d?.managed ? { running: this.connector.running, since: this.connector.since || null,
                                log: this.connector.lines.slice(-12) } : null,
      login: this.login ? { url: this.login.url, error: this.login.error, waiting: !!this.login.proc } : null,
      cert: null,
    };
    if (!d && existsSync(this.certPath())) {
      try { out.cert = { zone: this.settings.get("cfZone") || null }; } catch { /* unreadable */ }
    }
    return out;
  }

  // Step 1: get the authorization link. Resolves once the link is known;
  // the process keeps waiting for the user in the background.
  startLogin() {
    if (this.domain()) throw new Error("A domain is already linked. Unlink it first.");
    const bin = this.bin();
    if (!bin) throw new Error("cloudflared is not installed. Run `aegis doctor --fix`, or install it from Cloudflare.");
    if (this.login?.proc && this.login.url) return Promise.resolve({ url: this.login.url });
    rmSync(join(this.home, ".cloudflared", "cert.pem"), { force: true });
    mkdirSync(join(this.home, ".cloudflared"), { recursive: true, mode: 0o700 });
    const proc = spawn(bin, ["tunnel", "--no-autoupdate", "login"], {
      env: { ...process.env, HOME: this.home, TUNNEL_ORIGIN_CERT: join(this.home, ".cloudflared", "cert.pem") },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const login = { proc, url: null, error: null, started: Date.now(), out: "" };
    this.login = login;
    return new Promise((resolve, reject) => {
      const feed = (buf) => {
        login.out = (login.out + buf).slice(-4000);
        const m = LOGIN_URL_RE.exec(login.out);
        if (m && !login.url) { login.url = m[0]; resolve({ url: login.url }); }
      };
      proc.stdout.on("data", feed);
      proc.stderr.on("data", feed);
      proc.on("error", (e) => { login.error = e.message; login.proc = null; reject(e); });
      proc.on("exit", async (code) => {
        login.proc = null;
        const got = join(this.home, ".cloudflared", "cert.pem");
        if (code === 0 && existsSync(got)) {
          renameSync(got, this.certPath());
          try {
            const zone = await this.zoneOfCert();
            this.settings.set({ cfZone: zone });
            this.log("cf: authorized for zone", zone.name || zone.id);
          } catch (e) { login.error = e.message; }
        } else if (!login.error) {
          login.error = code === null ? "Cancelled." : (login.out.split("\n").filter((l) => /error|ERR|failed/i.test(l)).pop() || `cloudflared exited with ${code}`).slice(0, 300);
        }
        if (!login.url) reject(new Error(login.error || "cloudflared did not print a login link"));
      });
      setTimeout(() => { if (!login.url) { try { proc.kill(); } catch { /* gone */ } reject(new Error("cloudflared did not print a login link within 30 s")); } }, 30000);
    });
  }

  cancelLogin() {
    if (this.login?.proc) { try { this.login.proc.kill(); } catch { /* gone */ } }
    this.login = null;
    return { ok: true };
  }

  // Forget an authorization that was never used to link a domain.
  forgetCert() {
    if (this.domain()) throw new Error("Unlink the domain first.");
    rmSync(this.certPath(), { force: true });
    this.settings.set({ cfZone: null });
    this.login = null;
    return { ok: true };
  }

  // Step 2: create the tunnel and the dashboard's record, start the connector.
  async link(label) {
    label = String(label || "").trim().toLowerCase();
    if (!LABEL_RE.test(label)) throw new Error("Use 1-40 letters, digits and dashes (not at the ends).");
    if (this.domain()) throw new Error("A domain is already linked.");
    if (!existsSync(this.certPath())) throw new Error("Authorize Cloudflare first.");
    const bin = this.bin();
    if (!bin) throw new Error("cloudflared is not installed.");
    const cert = decodeCert(this.certPath());
    let zone = this.settings.get("cfZone");
    if (!zone?.name) zone = await this.zoneOfCert();
    if (!zone?.name) throw new Error("Could not read the zone name from Cloudflare.");
    const mainHost = `${label}.${zone.name}`.toLowerCase();

    const creds = join(this.dir, "tunnel.json");
    rmSync(creds, { force: true });
    const name = `aegis-${label}-${randomBytes(3).toString("hex")}`;
    const r = await run(bin, ["--origincert", this.certPath(), "tunnel", "--no-autoupdate", "create", "--credentials-file", creds, name],
                        { env: { ...process.env, HOME: this.home } });
    const id = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/.exec(r.out + r.err)?.[1];
    if (r.code !== 0 || !id || !existsSync(creds)) throw new Error(`cloudflared could not create the tunnel: ${(r.err || r.out).trim().split("\n").pop()}`);

    const target = `${id}.cfargotunnel.com`;
    try {
      const existing = await cfApi(cert.token, "GET", `/zones/${cert.zoneId}/dns_records?name=${encodeURIComponent(mainHost)}`);
      const rec = existing.find((x) => x.name === mainHost);
      const body = { type: "CNAME", name: mainHost, content: target, proxied: true, ttl: 1, comment: "aegis dashboard" };
      if (rec && rec.type !== "CNAME") throw new Error(`${mainHost} already has a ${rec.type} record. Pick another name.`);
      if (rec) await cfApi(cert.token, "PUT", `/zones/${cert.zoneId}/dns_records/${rec.id}`, body);
      else await cfApi(cert.token, "POST", `/zones/${cert.zoneId}/dns_records`, body);
    } catch (e) {
      await run(bin, ["--origincert", this.certPath(), "tunnel", "delete", "-f", id], { env: { ...process.env, HOME: this.home } });
      rmSync(creds, { force: true });
      throw e;
    }

    const domain = { mainHost, zone: { id: cert.zoneId, name: zone.name }, tunnelId: id, tunnelName: name,
                     cert: this.certPath(), creds, managed: true, linked: Date.now() };
    this.writeConfig(domain);
    this.settings.set({ domain });
    this.startConnector();
    this.log("cf: linked", mainHost, "tunnel", id);
    await this.onDomain?.(domain, "linked");
    return this.state();
  }

  // Give the dashboard another name on the same zone and tunnel: the new
  // record first, then the old one goes. Tunnels named after the dashboard
  // (tunnel-PORT-<name>) move with it; ones with a name of their own stay.
  async rename(label) {
    label = String(label || "").trim().toLowerCase();
    if (!LABEL_RE.test(label)) throw new Error("Use 1-40 letters, digits and dashes (not at the ends).");
    const d = this.domain();
    if (!d) throw new Error("No domain is linked yet.");
    if (!d.managed) throw new Error("This domain is routed by a cloudflared service Aegis does not manage; rename it there.");
    const zoneName = d.zone?.name || d.mainHost.split(".").slice(1).join(".");
    const mainHost = `${label}.${zoneName}`;
    if (mainHost === d.mainHost) return this.state();
    const cert = decodeCert(d.cert);
    const target = `${d.tunnelId}.cfargotunnel.com`;
    const existing = await cfApi(cert.token, "GET", `/zones/${cert.zoneId}/dns_records?name=${encodeURIComponent(mainHost)}`);
    const rec = existing.find((x) => x.name === mainHost);
    if (rec && !(rec.type === "CNAME" && rec.content === target)) throw new Error(`${mainHost} is already in use (a ${rec.type} record). Pick another name.`);
    if (!rec) await cfApi(cert.token, "POST", `/zones/${cert.zoneId}/dns_records`, { type: "CNAME", name: mainHost, content: target, proxied: true, ttl: 1, comment: "aegis dashboard" });
    await this.onDomain?.(d, "unlinking");
    try {
      const old = await cfApi(cert.token, "GET", `/zones/${cert.zoneId}/dns_records?name=${encodeURIComponent(d.mainHost)}`);
      for (const r of old) if (r.type === "CNAME" && r.content === target) await cfApi(cert.token, "DELETE", `/zones/${cert.zoneId}/dns_records/${r.id}`);
    } catch (e) { this.log("cf: could not remove the old dashboard record:", e.message); }
    const domain = { ...d, mainHost, renamed: Date.now() };
    this.settings.set({ domain });
    this.startConnector();
    this.log("cf: renamed", d.mainHost, "->", mainHost);
    await this.onDomain?.(domain, "linked");
    return this.state();
  }

  writeConfig(d) {
    const o = this.origin();
    const req = o.insecure ? "    originRequest:\n      noTLSVerify: true\n" : "";
    const yml = [
      "# Written by Aegis. Changes are overwritten when the domain is relinked.",
      `tunnel: ${d.tunnelId}`,
      `credentials-file: ${d.creds}`,
      "protocol: quic",
      "loglevel: info",
      "ingress:",
      `  - hostname: ${d.mainHost}`,
      `    service: ${o.url}`,
      req.trimEnd(),
      "  # tunnel-PORT-<name> addresses; only names whose DNS points at this",
      "  # tunnel ever arrive, and Aegis answers 404 for anything it doesn't know",
      `  - hostname: "*.${d.zone.name}"`,
      `    service: ${o.url}`,
      req.trimEnd(),
      "  - service: http_status:404",
      "",
    ].filter((l) => l !== "").join("\n") + "\n";
    writeFileSync(join(this.dir, "cloudflared.yml"), yml, { mode: 0o600 });
  }

  startConnector() {
    const d = this.domain();
    const bin = this.bin();
    if (!d?.managed || !bin) return;
    this.writeConfig(d);
    this.connector.stop();
    this.connector.start(bin, ["--no-autoupdate", "--config", join(this.dir, "cloudflared.yml"), "tunnel", "--post-quantum", "run"],
                         { HOME: this.home });
  }

  // Undo link(): records, tunnel, files. The certificate stays, so linking
  // again (maybe under another name) needs no new authorization.
  async unlink() {
    const d = this.domain();
    if (!d) return this.state();
    if (!d.managed) throw new Error("This domain is routed by a cloudflared service Aegis does not manage; change it there.");
    await this.onDomain?.(d, "unlinking");          // tunnel records first, while the token is known
    this.connector.stop();
    const bin = this.bin();
    try {
      const cert = decodeCert(d.cert);
      const recs = await cfApi(cert.token, "GET", `/zones/${cert.zoneId}/dns_records?name=${encodeURIComponent(d.mainHost)}`);
      for (const rec of recs) if (rec.type === "CNAME" && rec.content === `${d.tunnelId}.cfargotunnel.com`) await cfApi(cert.token, "DELETE", `/zones/${cert.zoneId}/dns_records/${rec.id}`);
    } catch (e) { this.log("cf: could not remove the dashboard record:", e.message); }
    if (bin) {
      await run(bin, ["--origincert", d.cert, "tunnel", "cleanup", d.tunnelId], { env: { ...process.env, HOME: this.home } });
      const r = await run(bin, ["--origincert", d.cert, "tunnel", "delete", "-f", d.tunnelId], { env: { ...process.env, HOME: this.home } });
      if (r.code !== 0) this.log("cf: tunnel delete:", (r.err || r.out).trim().split("\n").pop());
    }
    rmSync(d.creds || join(this.dir, "tunnel.json"), { force: true });
    rmSync(join(this.dir, "cloudflared.yml"), { force: true });
    this.settings.set({ domain: null });
    await this.onDomain?.(null, "unlinked");
    this.log("cf: unlinked", d.mainHost);
    return this.state();
  }

  stop() { this.connector.stop(); this.cancelLogin(); }
}
