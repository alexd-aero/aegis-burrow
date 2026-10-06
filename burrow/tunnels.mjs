// Burrow, the engine: the tunnel manager.
//
// A tunnel publishes one local (or LAN) port on its own HTTPS address. Burrow
// has no login of its own: Aegis, in front of it, decides who gets through
// (a tunnel is login-protected unless it is public).
//
// With a linked domain (cloudflare.mjs) the address is
//   https://tunnel-<PORT>-<label>.<zone>        e.g. tunnel-3000-aegis.example.com
// through the same named Cloudflare tunnel as the dashboard, or a name of the
// user's own choosing (t.sub):
//   https://<sub>.<zone>                        e.g. grafana.example.com
// Both are one level under the zone, so Cloudflare's free certificate covers
// them. (The dotted form tunnel-<PORT>.<label>.<zone> is accepted too, for
// zones whose certificate covers two levels.)
//
// Without a domain every tunnel gets its own random *.trycloudflare.com
// address instead (QuickTunnels): no account, but a new name after a restart.
//
// Everything a tunnel does is counted here: requests, bytes, status codes,
// latency, WebSockets, and every client that used it.

import { request as httpRequest, Agent as HttpAgent } from "node:http";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { execFile } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";

const MINUTES = 120;            // per-minute history kept
const SECONDS = 90;             // per-second history for the live chart
const RECENT = 150;             // recent requests kept
const LAT_SAMPLES = 600;        // latency samples for percentiles
const MAX_CLIENTS = 500;        // per tunnel
const HEALTH_EVERY_MS = 15000;
const FAVICON_EVERY_MS = 6 * 3600 * 1000;
// Never HTTP: not worth offering as a tunnel (ssh, smtp, dns, samba, ipp-less extras).
const SUB_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const NOT_HTTP = new Set([22, 25, 53, 111, 139, 445, 465, 587, 993, 995, 1194, 3306, 5432, 6379, 27017]);

const httpAgent = new HttpAgent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new HttpsAgent({ keepAlive: true, maxSockets: 256, rejectUnauthorized: false });

const now = () => Date.now();
const minuteOf = (t) => Math.floor(t / 60000);
const secondOf = (t) => Math.floor(t / 1000);

function percentile(arr, p) {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
}

export function parseUA(ua = "") {
  const b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl\//i.test(ua) ? "curl"
    : /wget/i.test(ua) ? "wget" : /bot|crawl|spider|preview/i.test(ua) ? "Bot"
    : /python|node|go-http|axios|okhttp|java/i.test(ua) ? "Script" : ua ? "Other" : "Unknown";
  const o = /Windows/.test(ua) ? "Windows" : /iPhone|iPad|iOS/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
  return o ? `${b} · ${o}` : b;
}

function newStats() {
  return {
    requests: 0, bytesIn: 0, bytesOut: 0, errors: 0, ws: 0,
    status: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 },
    minutes: [],    // [{m, req, inB, outB, err, latSum, latN}]
    first: null, last: null,
  };
}

function bucket(list, key, value, max) {
  let b = list.length && list[list.length - 1];
  if (!b || b.k !== value) {
    b = { k: value, req: 0, inB: 0, outB: 0, err: 0, latSum: 0, latN: 0 };
    list.push(b);
    while (list.length > max) list.shift();
  }
  return b;
}

export class TunnelManager {
  constructor({ dataDir, domain, quick, forbiddenPorts, log }) {
    this.dataDir = dataDir;
    this.quick = quick;                       // QuickTunnels, used while no domain is linked
    this.forbidden = new Set(forbiddenPorts || []);
    this.log = log || console.log;
    this.tunnels = new Map();     // port -> config
    this.live = new Map();        // port -> runtime (stats, clients, recent, sockets, health)
    mkdirSync(join(dataDir, "favicons"), { recursive: true });
    this.load();
    this.useDomain(domain);
    this.saveTimer = setInterval(() => this.save(), 30000);
    this.healthTimer = setInterval(() => this.healthAll(), HEALTH_EVERY_MS);
    setTimeout(() => this.healthAll(), 1500);
  }

  // ------------------------------------------------------------- naming
  // domain = { mainHost, tunnelId, cert } or null (quick tunnels)
  useDomain(domain) {
    this.domain = domain && domain.mainHost ? domain : null;
    this._cf = null;
    if (this.domain) {
      const main = this.domain.mainHost.toLowerCase();
      const dot = main.indexOf(".");
      this.label = main.slice(0, dot);          // aegis
      this.parent = main.slice(dot + 1);        // example.com
      this.hostRe = new RegExp(`^tunnel-(\\d{1,5})(?:-|\\.)${this.label.replace(/[-.]/g, "\\$&")}\\.${this.parent.replace(/[-.]/g, "\\$&")}$`);
      this.quick?.stopAll();
    } else {
      this.label = this.parent = this.hostRe = null;
      for (const port of this.tunnels.keys()) this.quick?.start(port);
    }
  }
  get mode() { return this.domain ? "domain" : "quick"; }
  hostFor(port) {
    const sub = this.tunnels.get(Number(port))?.sub;
    if (this.domain) return sub ? `${sub}.${this.parent}` : `tunnel-${port}-${this.label}.${this.parent}`;
    return this.quick?.host(port) || null;
  }
  urlFor(port) { const h = this.hostFor(port); return h ? `https://${h}` : null; }
  pattern() { return this.domain ? `tunnel-PORT-${this.label}.${this.parent}` : "a random name on trycloudflare.com"; }
  matchHost(host) {
    const name = String(host || "").toLowerCase().split(":")[0];
    if (this.hostRe) {
      for (const t of this.tunnels.values()) if (t.sub && name === `${t.sub}.${this.parent}`) return t.port;
      const m = this.hostRe.exec(name);
      return m && !this.tunnels.get(Number(m[1]))?.sub ? Number(m[1]) : null;
    }
    const port = this.quick?.portOf(name);
    return port == null ? null : port;
  }

  // ------------------------------------------------------------- persistence
  file(name) { return join(this.dataDir, name); }
  load() {
    try {
      const cfg = JSON.parse(readFileSync(this.file("tunnels.json"), "utf8"));
      for (const t of cfg.tunnels || []) this.tunnels.set(t.port, t);
    } catch { /* first run */ }
    let saved = {};
    try { saved = JSON.parse(readFileSync(this.file("metrics.json"), "utf8")); } catch { /* none */ }
    for (const port of this.tunnels.keys()) this.runtime(port, saved[port]);
  }
  save() {
    const write = (name, obj) => {
      const tmp = this.file(name + ".tmp");
      writeFileSync(tmp, JSON.stringify(obj));
      renameSync(tmp, this.file(name));
    };
    try {
      write("tunnels.json", { tunnels: [...this.tunnels.values()] });
      const m = {};
      for (const [port, rt] of this.live) {
        m[port] = { stats: rt.stats, clients: [...rt.clients.values()].map(({ sockets, ...c }) => ({ ...c, active: 0 })),
                    recent: rt.recent, lat: rt.lat.slice(-200), favicon: rt.favicon, title: rt.title };
      }
      write("metrics.json", m);
    } catch (e) { this.log("tunnels: save failed", e.message); }
  }
  runtime(port, saved) {
    if (!this.live.has(port)) {
      const rt = {
        stats: saved?.stats || newStats(), seconds: [], lat: saved?.lat || [],
        clients: new Map((saved?.clients || []).map((c) => [c.ip, { ...c, active: 0, sockets: new Set() }])),
        recent: saved?.recent || [], inflight: 0, wsActive: 0,
        health: { up: null, ms: null, checked: null, history: [], since: null },
        favicon: saved?.favicon || null, title: saved?.title || null, faviconAt: 0,
      };
      this.live.set(port, rt);
    }
    return this.live.get(port);
  }

  // ------------------------------------------------------------- CRUD
  list() { return [...this.tunnels.values()].sort((a, b) => a.port - b.port).map((t) => this.summary(t)); }
  get(port) { return this.tunnels.get(Number(port)); }

  // A name of the user's own for a tunnel: "grafana" -> grafana.<zone>.
  // "" or null goes back to tunnel-PORT-<label>.
  async checkSub(port, sub) {
    if (sub == null || sub === "") return null;
    sub = String(sub).trim().toLowerCase().replace(/\.$/, "");
    if (this.parent && sub.endsWith("." + this.parent)) sub = sub.slice(0, -this.parent.length - 1);
    if (!SUB_RE.test(sub)) throw new Error("A name is 1-40 letters, digits and dashes (not at the ends), like grafana.");
    if (/^tunnel-\d+-/.test(sub)) throw new Error("Names that start with tunnel-PORT- are Burrow's own; pick another.");
    if (this.domain && sub === this.label) throw new Error("That is the dashboard's own name.");
    for (const t of this.tunnels.values()) if (t.port !== port && t.sub === sub) throw new Error(`tunnel-${t.port} already uses ${sub}.`);
    if (this.domain) {
      // never take over a record that isn't ours (mail, www, a website…)
      const name = `${sub}.${this.parent}`;
      const recs = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`);
      const other = recs.find((r) => !(r.type === "CNAME" && r.content === `${this.domain.tunnelId}.cfargotunnel.com`));
      if (other) throw new Error(`${name} already has a ${other.type} record on Cloudflare. Pick another name, or delete that record first.`);
    }
    return sub;
  }

  async create(spec) {
    const port = Number(spec.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Pick a port from 1 to 65535.");
    if (this.forbidden.has(port)) throw new Error("That is Aegis itself.");
    if (this.tunnels.has(port)) throw new Error(`tunnel-${port} already exists.`);
    const targetHost = String(spec.targetHost || "127.0.0.1").trim() || "127.0.0.1";
    if (!/^[a-zA-Z0-9.\-:\[\]]{1,253}$/.test(targetHost)) throw new Error("That target host does not look right.");
    const targetPort = Number(spec.targetPort || port);
    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) throw new Error("Target port must be 1-65535.");
    const sub = await this.checkSub(port, spec.sub);
    const t = {
      sub,
      port, targetHost, targetPort,
      scheme: ["http", "https"].includes(spec.scheme) ? spec.scheme : await this.detectScheme(targetHost, targetPort),
      name: String(spec.name || "").slice(0, 60),
      access: spec.access === "public" ? "public" : "login",
      preserveHost: !!spec.preserveHost,
      enabled: true, created: now(), blocked: [], dns: null,
    };
    this.tunnels.set(port, t);
    this.runtime(port);
    this.save();
    await this.publish(port);
    this.save();
    this.refreshFavicon(port, true);
    this.healthOne(port);
    this.log("tunnels: created", port, "->", `${t.scheme}://${t.targetHost}:${t.targetPort}`, t.access);
    return this.summary(t);
  }

  async update(port, patch) {
    const t = this.get(port);
    if (!t) throw new Error("No such tunnel.");
    if ("enabled" in patch) {
      t.enabled = !!patch.enabled;
      if (!t.enabled) this.kick(port, null);
    }
    if ("access" in patch) t.access = patch.access === "public" ? "public" : "login";
    if ("name" in patch) t.name = String(patch.name || "").slice(0, 60);
    if ("preserveHost" in patch) t.preserveHost = !!patch.preserveHost;
    if ("scheme" in patch && ["http", "https"].includes(patch.scheme)) t.scheme = patch.scheme;
    if ("targetHost" in patch || "targetPort" in patch) {
      if (patch.targetHost) t.targetHost = String(patch.targetHost).trim();
      if (patch.targetPort) t.targetPort = Number(patch.targetPort);
      t.scheme = await this.detectScheme(t.targetHost, t.targetPort);
      this.refreshFavicon(port, true);
    }
    if (patch.block) { if (!t.blocked.includes(patch.block)) t.blocked.push(patch.block); this.kick(port, patch.block); }
    if (patch.unblock) t.blocked = t.blocked.filter((ip) => ip !== patch.unblock);
    if ("sub" in patch) {
      const sub = await this.checkSub(t.port, patch.sub);
      if (sub !== (t.sub || null)) {
        if (this.domain) await this.unpublish(t.port);          // the old name's record goes
        t.sub = sub;
        t.dns = null;
        this.log("tunnels:", t.port, "is now at", this.hostFor(t.port) || `${sub || "its default name"} (once a domain is linked)`);
      }
    }
    if (patch.resetStats) { const rt = this.runtime(port); rt.stats = newStats(); rt.recent = []; rt.lat = []; rt.clients = new Map(); }
    if (this.domain && (!t.dns || t.dns.error)) await this.publish(port);
    this.save();
    return this.summary(t);
  }

  async remove(port) {
    const t = this.get(port);
    if (!t) throw new Error("No such tunnel.");
    this.kick(port, null);
    this.tunnels.delete(t.port);
    this.live.delete(t.port);
    try { if (existsSync(this.file(`favicons/${t.port}`))) unlinkSync(this.file(`favicons/${t.port}`)); } catch { /* ignore */ }
    this.save();
    const dns = await this.unpublish(t.port);
    this.log("tunnels: removed", t.port, "dns", dns);
    return { removed: t.port, dns };
  }

  // Give a tunnel its public name: a DNS record on the linked domain, or a
  // quick tunnel of its own.
  async publish(port) {
    const t = this.get(port);
    if (!t) return;
    if (!this.domain) { t.dns = null; this.quick?.start(port); return; }
    try {
      t.dns = await this.dnsCreate(this.hostFor(port));
    } catch (e) {
      t.dns = { error: e.message };
      this.log("tunnels: DNS create failed for", port, e.message);
    }
  }
  async unpublish(port) {
    if (!this.domain) { this.quick?.stop(port); return "none"; }
    try { return await this.dnsDelete(this.hostFor(port)); } catch (e) { return "error: " + e.message; }
  }
  // A domain was just linked: every tunnel gets its record.
  async publishAll() {
    for (const port of this.tunnels.keys()) await this.publish(port);
    this.save();
  }
  // The domain is about to be unlinked: take every record down first.
  async unpublishAll() {
    for (const port of this.tunnels.keys()) {
      await this.unpublish(port);
      const t = this.get(port);
      if (t) t.dns = null;
    }
    this.save();
  }

  kick(port, ip) {
    const rt = this.live.get(Number(port));
    if (!rt) return 0;
    let n = 0;
    for (const c of rt.clients.values()) {
      if (ip && c.ip !== ip) continue;
      for (const s of c.sockets) { try { s.destroy(); n++; } catch { /* gone */ } }
      c.sockets.clear();
    }
    return n;
  }

  // ------------------------------------------------------------- views
  summary(t) {
    const rt = this.runtime(t.port);
    const m = minuteOf(now());
    const recentMin = rt.stats.minutes.filter((b) => b.k > m - 5);
    const reqPerMin = recentMin.length ? recentMin.reduce((a, b) => a + b.req, 0) / Math.min(5, Math.max(1, m - recentMin[0].k + 1)) : 0;
    const spark = [];
    const byMin = new Map(rt.stats.minutes.map((b) => [b.k, b]));
    for (let i = 59; i >= 0; i--) spark.push(byMin.get(m - i)?.req || 0);
    const online = [...rt.clients.values()].filter((c) => c.active > 0 || now() - c.last < 120000).length;
    const quick = this.domain ? null : this.quick?.status(t.port);
    return {
      port: t.port, url: this.urlFor(t.port), host: this.hostFor(t.port), mode: this.mode,
      quick: quick ? { state: quick.state, error: quick.error } : null,
      target: `${t.scheme}://${t.targetHost}:${t.targetPort}`, targetHost: t.targetHost, targetPort: t.targetPort,
      scheme: t.scheme, name: t.name, sub: t.sub || null, title: rt.title, access: t.access, preserveHost: t.preserveHost,
      enabled: t.enabled, created: t.created, blocked: t.blocked, dns: t.dns,
      favicon: rt.favicon ? `/__gate/api/tunnels/${t.port}/favicon?v=${rt.favicon.at}` : null,
      health: { up: rt.health.up, ms: rt.health.ms, checked: rt.health.checked },
      totals: { requests: rt.stats.requests, bytesIn: rt.stats.bytesIn, bytesOut: rt.stats.bytesOut,
                errors: rt.stats.errors, ws: rt.stats.ws, last: rt.stats.last },
      active: rt.inflight + rt.wsActive, wsActive: rt.wsActive, reqPerMin: Math.round(reqPerMin * 10) / 10,
      clients: rt.clients.size, online, spark,
    };
  }

  details(port) {
    const t = this.get(port);
    if (!t) return null;
    const rt = this.runtime(t.port);
    const m = minuteOf(now()), s = secondOf(now());
    const byMin = new Map(rt.stats.minutes.map((b) => [b.k, b]));
    const minutes = [];
    for (let i = MINUTES - 1; i >= 0; i--) {
      const b = byMin.get(m - i);
      minutes.push({ t: (m - i) * 60000, req: b?.req || 0, inB: b?.inB || 0, outB: b?.outB || 0, err: b?.err || 0,
                     lat: b && b.latN ? Math.round(b.latSum / b.latN) : null });
    }
    const bySec = new Map(rt.seconds.map((b) => [b.k, b]));
    const seconds = [];
    for (let i = 59; i >= 0; i--) { const b = bySec.get(s - i); seconds.push({ t: (s - i) * 1000, req: b?.req || 0, outB: b?.outB || 0 }); }
    const clients = [...rt.clients.values()].map(({ sockets, ...c }) => c)
      .sort((a, b) => (b.active - a.active) || (b.last - a.last)).slice(0, 200);
    return {
      ...this.summary(t),
      status: rt.stats.status, first: rt.stats.first,
      latency: { p50: percentile(rt.lat, 50), p95: percentile(rt.lat, 95), p99: percentile(rt.lat, 99) },
      minutes, seconds, clientList: clients, recent: rt.recent.slice(-100).reverse(),
      healthHistory: rt.health.history.slice(-40), healthSince: rt.health.since,
    };
  }

  // ------------------------------------------------------------- traffic
  client(rt, req) {
    const ip = String(req.headers["cf-connecting-ip"] || req.socket.remoteAddress || "?");
    let c = rt.clients.get(ip);
    if (!c) {
      if (rt.clients.size >= MAX_CLIENTS) {
        const oldest = [...rt.clients.values()].filter((x) => !x.active).sort((a, b) => a.last - b.last)[0];
        if (oldest) rt.clients.delete(oldest.ip);
      }
      c = { ip, country: "", agent: "", first: now(), last: now(), requests: 0, bytesIn: 0, bytesOut: 0, ws: 0, active: 0, sockets: new Set() };
      rt.clients.set(ip, c);
    }
    c.country = String(req.headers["cf-ipcountry"] || c.country || "");
    if (req.headers["user-agent"]) c.agent = parseUA(req.headers["user-agent"]);
    c.last = now();
    return c;
  }

  record(rt, c, { method, path, status, ms, inB, outB, error }) {
    const st = rt.stats, t = now();
    st.requests++; st.bytesIn += inB; st.bytesOut += outB;
    if (!st.first) st.first = t;
    st.last = t;
    const cls = status ? `${Math.floor(status / 100)}xx` : null;
    if (cls && st.status[cls] !== undefined) st.status[cls]++;
    if (error || status >= 500) st.errors++;
    const mb = bucket(st.minutes, null, minuteOf(t), MINUTES);
    mb.req++; mb.inB += inB; mb.outB += outB; if (error || status >= 500) mb.err++;
    if (ms != null) { mb.latSum += ms; mb.latN++; rt.lat.push(ms); if (rt.lat.length > LAT_SAMPLES) rt.lat.shift(); }
    const sb = bucket(rt.seconds, null, secondOf(t), SECONDS);
    sb.req++; sb.outB += outB;
    c.requests++; c.bytesIn += inB; c.bytesOut += outB;
    rt.recent.push({ t, ip: c.ip, country: c.country, method, path: String(path).slice(0, 160), status: status || 0, ms, bytes: outB, error: error || undefined });
    if (rt.recent.length > RECENT) rt.recent.shift();
  }

  upstreamHeaders(t, req, extra) {
    const h = { ...req.headers, ...extra };
    if (!t.preserveHost) {
      h.host = `${t.targetHost}:${t.targetPort}`;
      // Apps compare Origin/Referer with Host (CSRF and WebSocket checks), so
      // rewrite our public origin to the upstream one, as Host was.
      const pub = `https://${String(req.headers.host || "").toLowerCase()}`;
      const upOrigin = `${t.scheme}://${h.host}`;
      if (h.origin && h.origin.toLowerCase() === pub) h.origin = upOrigin;
      if (h.referer && (h.referer.toLowerCase() + "/").startsWith(pub + "/")) h.referer = upOrigin + h.referer.slice(pub.length);
    }
    h["x-forwarded-for"] = String(req.headers["cf-connecting-ip"] || req.socket.remoteAddress || "");
    h["x-forwarded-proto"] = "https";
    h["x-forwarded-host"] = req.headers.host || "";
    return h;
  }

  // HTTP request to a tunnel host that is allowed through (auth done by caller)
  proxy(port, req, res, { stripCookie }) {
    const t = this.get(port), rt = this.runtime(port);
    const c = this.client(rt, req);
    if (t.blocked.includes(c.ip)) { res.writeHead(403, { "Content-Type": "text/plain" }); res.end("Blocked."); return; }
    const started = now();
    let inB = 0, outB = 0, done = false, status = 0;
    rt.inflight++; c.active++;
    c.sockets.add(req.socket);
    const finish = (error) => {
      if (done) return; done = true;
      rt.inflight--; c.active = Math.max(0, c.active - 1);
      c.sockets.delete(req.socket);
      this.record(rt, c, { method: req.method, path: req.url, status, ms: now() - started, inB, outB, error });
    };
    const headers = this.upstreamHeaders(t, req, {});
    const cookie = stripCookie(headers.cookie);
    if (cookie) headers.cookie = cookie; else delete headers.cookie;
    const mod = t.scheme === "https" ? httpsRequest : httpRequest;
    const up = mod({ host: t.targetHost, port: t.targetPort, method: req.method, path: req.url, headers,
                     agent: t.scheme === "https" ? httpsAgent : httpAgent, timeout: 120000 }, (upRes) => {
      status = upRes.statusCode;
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.on("data", (d) => { outB += d.length; });
      upRes.pipe(res);
      upRes.on("end", () => finish());
      upRes.on("error", () => finish("upstream reset"));
    });
    up.on("timeout", () => up.destroy(new Error("timeout")));
    up.on("error", (e) => {
      if (!res.headersSent) {
        status = 502;
        res.writeHead(502, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
        res.end(this.offlinePage(t, e.code || e.message));
      } else res.destroy();
      finish(e.code || e.message);
    });
    req.on("data", (d) => { inB += d.length; });
    res.on("close", () => finish(done ? undefined : (status ? undefined : "client closed")));
    req.pipe(up);
  }

  proxyUpgrade(port, req, socket, head, { stripCookie }) {
    const t = this.get(port), rt = this.runtime(port);
    const c = this.client(rt, req);
    if (t.blocked.includes(c.ip)) { socket.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
    const headers = this.upstreamHeaders(t, req, {});
    const cookie = stripCookie(headers.cookie);
    if (cookie) headers.cookie = cookie; else delete headers.cookie;
    const mod = t.scheme === "https" ? httpsRequest : httpRequest;
    const started = now();
    const up = mod({ host: t.targetHost, port: t.targetPort, method: req.method, path: req.url, headers,
                     rejectUnauthorized: false });
    up.on("upgrade", (upRes, upSocket, upHead) => {
      const lines = [`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}`];
      for (let i = 0; i < upRes.rawHeaders.length; i += 2) lines.push(`${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}`);
      socket.write(lines.join("\r\n") + "\r\n\r\n");
      if (upHead?.length) socket.write(upHead);
      if (head?.length) upSocket.write(head);
      rt.wsActive++; c.active++; c.ws++; rt.stats.ws++;
      c.sockets.add(socket);
      let inB = 0, outB = 0, closed = false;
      socket.on("data", (d) => { inB += d.length; });
      upSocket.on("data", (d) => { outB += d.length; });
      const close = () => {
        if (closed) return; closed = true;
        rt.wsActive--; c.active = Math.max(0, c.active - 1); c.sockets.delete(socket);
        this.record(rt, c, { method: "WS", path: req.url, status: 101, ms: now() - started, inB, outB });
        socket.destroy(); upSocket.destroy();
      };
      upSocket.pipe(socket).pipe(upSocket);
      socket.on("close", close); upSocket.on("close", close);
      socket.on("error", close); upSocket.on("error", close);
    });
    up.on("response", (upRes) => { socket.end(`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n\r\n`); });
    up.on("error", () => socket.destroy());
    up.end();
  }

  offlinePage(t, why) {
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#030304;color:#e8eaed;font:14px/1.5 system-ui,sans-serif}
.c{max-width:380px;padding:28px 30px;border:1px solid rgba(255,255,255,.1);border-radius:16px;background:#0f1012}
h1{font-size:17px;margin:0 0 6px}p{margin:0;color:#8a8f97}code{font:12px ui-monospace,monospace;color:#c9ccd1}</style></head>
<body><div class="c"><h1>Nothing is answering</h1><p>This tunnel is up, but <code>${t.targetHost}:${t.targetPort}</code> did not respond (<code>${String(why).replace(/[<>&]/g, "")}</code>).</p></div></body></html>`;
  }

  // ------------------------------------------------------------- target health
  probe(host, port, timeout = 2500) {
    return new Promise((resolve) => {
      const t0 = now();
      const s = netConnect({ host, port, timeout });
      const end = (up) => { s.destroy(); resolve({ up, ms: up ? now() - t0 : null }); };
      s.once("connect", () => end(true));
      s.once("timeout", () => end(false));
      s.once("error", () => end(false));
    });
  }
  detectScheme(host, port) {
    return new Promise((resolve) => {
      const s = tlsConnect({ host, port, rejectUnauthorized: false, timeout: 1500, servername: /^[\d.:]+$/.test(host) ? undefined : host });
      const end = (v) => { s.destroy(); resolve(v); };
      s.once("secureConnect", () => end("https"));
      s.once("timeout", () => end("http"));
      s.once("error", () => end("http"));
    });
  }
  async healthOne(port) {
    const t = this.get(port);
    if (!t) return;
    const rt = this.runtime(port);
    const r = await this.probe(t.targetHost, t.targetPort);
    if (rt.health.up !== r.up) rt.health.since = now();
    rt.health.up = r.up; rt.health.ms = r.ms; rt.health.checked = now();
    rt.health.history.push({ t: now(), up: r.up, ms: r.ms });
    if (rt.health.history.length > 240) rt.health.history.shift();
    if (r.up && t.enabled && now() - rt.faviconAt > FAVICON_EVERY_MS) this.refreshFavicon(port);
  }
  healthAll() { for (const port of this.tunnels.keys()) this.healthOne(port); }

  // ------------------------------------------------------------- favicon + title
  fetchTarget(t, path, limit) {
    return new Promise((resolve) => {
      const mod = t.scheme === "https" ? httpsRequest : httpRequest;
      const req = mod({ host: t.targetHost, port: t.targetPort, path, method: "GET", timeout: 5000, rejectUnauthorized: false,
                        headers: { host: (t.preserveHost && this.hostFor(t.port)) || `${t.targetHost}:${t.targetPort}`,
                                   "user-agent": "aegis/1 (favicon)", accept: "*/*" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && limit > 0) {
          res.resume();
          try {
            const u = new URL(res.headers.location, `${t.scheme}://${t.targetHost}:${t.targetPort}${path}`);
            if (u.hostname === t.targetHost || u.hostname === "localhost" || u.hostname === this.hostFor(t.port)) {
              return resolve(this.fetchTarget(t, u.pathname + u.search, limit - 1));
            }
          } catch { /* ignore */ }
          return resolve(null);
        }
        const chunks = []; let size = 0;
        res.on("data", (d) => { size += d.length; if (size > 600000) { req.destroy(); } else chunks.push(d); });
        res.on("end", () => resolve({ status: res.statusCode, type: String(res.headers["content-type"] || ""), body: Buffer.concat(chunks), path }));
        res.on("error", () => resolve(null));
      });
      req.on("timeout", () => req.destroy());
      req.on("error", () => resolve(null));
      req.end();
    });
  }
  async refreshFavicon(port, force) {
    const t = this.get(port);
    if (!t) return;
    const rt = this.runtime(port);
    if (!force && now() - rt.faviconAt < 60000) return;
    rt.faviconAt = now();
    const page = await this.fetchTarget(t, "/", 3);
    const candidates = [];
    if (page && page.status < 400 && /html/i.test(page.type)) {
      const html = page.body.toString("utf8", 0, 200000);
      const title = /<title[^>]*>([^<]{1,140})<\/title>/i.exec(html);
      rt.title = title ? title[1].replace(/\s+/g, " ").trim() : rt.title;
      const links = html.match(/<link\b[^>]*>/gi) || [];
      const scored = [];
      for (const l of links) {
        const rel = /rel\s*=\s*["']?([^"'>]+)/i.exec(l)?.[1]?.toLowerCase() || "";
        const href = /href\s*=\s*["']([^"']+)["']/i.exec(l)?.[1];
        if (!href || !/icon/.test(rel)) continue;
        const sizes = /sizes\s*=\s*["']?(\d+)/i.exec(l)?.[1];
        scored.push({ href, score: (rel.includes("apple") ? 2 : 3) * 1000 + Math.min(Number(sizes || 32), 256) });
      }
      scored.sort((a, b) => b.score - a.score);
      for (const s of scored) {
        try { const u = new URL(s.href, `http://x${page.path}`); if (u.host === "x") candidates.push(u.pathname + u.search); }
        catch { /* skip */ }
        if (/^data:image\//.test(s.href)) {
          const m = /^data:(image\/[\w+.-]+);base64,(.+)$/.exec(s.href);
          if (m) { this.storeFavicon(rt, port, m[1], Buffer.from(m[2], "base64")); return; }
        }
      }
    }
    candidates.push("/favicon.ico", "/favicon.svg", "/favicon.png");
    for (const path of candidates.slice(0, 6)) {
      const r = await this.fetchTarget(t, path, 2);
      if (!r || r.status >= 400 || !r.body.length || r.body.length > 512000) continue;
      const type = r.type.split(";")[0].trim();
      const sniff = r.body.subarray(0, 4).toString("hex");
      const looks = /^image\//.test(type) || sniff === "00000100" || sniff.startsWith("89504e47") || r.body.toString("utf8", 0, 200).includes("<svg");
      if (!looks || /html/.test(type)) continue;
      const finalType = /^image\//.test(type) ? type : sniff === "00000100" ? "image/x-icon" : sniff.startsWith("89504e47") ? "image/png" : "image/svg+xml";
      this.storeFavicon(rt, port, finalType, r.body);
      return;
    }
  }
  storeFavicon(rt, port, type, body) {
    try {
      writeFileSync(this.file(`favicons/${port}`), body);
      rt.favicon = { type: type === "image/svg+xml" ? "image/svg+xml" : type, at: now() };
    } catch (e) { this.log("tunnels: favicon store failed", e.message); }
  }
  favicon(port) {
    const rt = this.live.get(Number(port));
    if (!rt?.favicon) return null;
    try { return { type: rt.favicon.type, body: readFileSync(this.file(`favicons/${Number(port)}`)) }; }
    catch { return null; }
  }

  // ------------------------------------------------------------- DNS (Cloudflare API)
  cf() {
    if (this._cf) return this._cf;
    if (!this.domain?.cert) throw new Error("No Cloudflare certificate.");
    const pem = readFileSync(this.domain.cert, "utf8");
    const b64 = /-----BEGIN [A-Z ]+-----\s*([\s\S]+?)\s*-----END/.exec(pem)[1].replace(/\s+/g, "");
    const d = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
    this._cf = { zone: d.zoneID, token: d.apiToken };
    return this._cf;
  }
  async cfApi(method, path, body) {
    const { zone, token } = this.cf();
    const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${zone}${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15000),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.success) throw new Error((j.errors || []).map((e) => e.message).join("; ") || `HTTP ${r.status}`);
    return j.result;
  }
  async dnsCreate(name) {
    const content = `${this.domain.tunnelId}.cfargotunnel.com`;
    const existing = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`);
    const rec = existing.find((r) => r.name === name);
    if (rec && rec.type === "CNAME" && rec.content === content && rec.proxied) return { id: rec.id, name, ok: true };
    if (rec) {
      const r = await this.cfApi("PUT", `/dns_records/${rec.id}`, { type: "CNAME", name, content, proxied: true, ttl: 1 });
      return { id: r.id, name, ok: true };
    }
    const r = await this.cfApi("POST", "/dns_records", { type: "CNAME", name, content, proxied: true, ttl: 1,
                                                         comment: "aegis (burrow tunnels)" });
    return { id: r.id, name, ok: true };
  }
  async dnsDelete(name) {
    const content = `${this.domain.tunnelId}.cfargotunnel.com`;
    const recs = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`);
    let n = 0;
    for (const r of recs) {
      if (r.type === "CNAME" && r.content === content) { await this.cfApi("DELETE", `/dns_records/${r.id}`); n++; }
    }
    return n ? "deleted" : "none";
  }

  // ------------------------------------------------------------- port discovery
  ports() {
    const run = (cmd, args) => new Promise((resolve) => execFile(cmd, args, { timeout: 8000 }, (e, out) => resolve(e ? "" : String(out))));
    return Promise.all([run("ss", ["-Htlnp"]), run("docker", ["ps", "--format", "{{.Names}}\t{{.Ports}}"])]).then(([ss, dps]) => {
      const byPort = new Map();
      const docker = new Map();
      for (const line of dps.split("\n")) {
        const [name, ports] = line.split("\t");
        for (const m of String(ports || "").matchAll(/(?:[\d.]+|\[::\]|::):(\d+)->(\d+)\/tcp/g)) docker.set(Number(m[1]), `${name} (${m[2]})`);
      }
      for (const line of ss.split("\n")) {
        const f = line.trim().split(/\s+/);
        if (f.length < 4) continue;
        const local = f[3];
        const port = Number(local.slice(local.lastIndexOf(":") + 1));
        const addr = local.slice(0, local.lastIndexOf(":")).replace(/^\[|\]$/g, "");
        if (!port || addr.startsWith("127.0.0.5") || addr.includes("%lo")) continue;
        const proc = /users:\(\("([^"]+)"/.exec(line)?.[1] || "";
        const cur = byPort.get(port) || { port, addrs: [], process: "" };
        if (!cur.addrs.includes(addr)) cur.addrs.push(addr);
        cur.process = docker.get(port) || cur.process || (proc && proc !== "docker-proxy" ? proc : "");
        byPort.set(port, cur);
      }
      return [...byPort.values()]
        .filter((p) => !this.forbidden.has(p.port) && !NOT_HTTP.has(p.port) && p.process !== "cloudflared")
        .map((p) => ({ ...p, local: p.addrs.some((a) => a === "0.0.0.0" || a === "::" || a === "*" || a.startsWith("127.") || a === "::1"),
                       tunneled: this.tunnels.has(p.port) }))
        // containers and named web servers first, then the rest by port
        .sort((a, b) => (/\(/.test(b.process) - /\(/.test(a.process)) || (!!b.process - !!a.process) || a.port - b.port);
    });
  }

  stop() { clearInterval(this.saveTimer); clearInterval(this.healthTimer); this.quick?.stopAll(); this.save(); }
}
