// Burrow, the engine: the tunnel manager.
//
// A tunnel publishes one local (or LAN) port on its own HTTPS address. Burrow
// has no login of its own: Aegis, in front of it, decides who gets through
// (the Aegis login by default, a password of its own, or no lock: public).
//
// With a linked domain (cloudflare.mjs) the address is
//   https://tunnel-<PORT>-<label>.<zone>        e.g. tunnel-3000-aegis.example.com
// through the same named Cloudflare tunnel as the dashboard, or a name of the
// user's own choosing (t.sub):
//   https://<sub>.<zone>                        e.g. grafana.example.com
// Both are one level under the zone, so Cloudflare's free certificate covers
// them. (The dotted form tunnel-<PORT>.<label>.<zone> is accepted too, for
// zones whose certificate covers two levels.) Each of those names is a DNS
// record of its own, made when the tunnel is.
//
// Or, with naming {mode: "wildcard", prefix} (Settings → Domain), one wildcard
// record serves every tunnel and nothing is added per tunnel:
//   https://<name>.<prefix>.<zone>              e.g. radio.tunnel.example.com
// where <name> is t.sub, or the port when it has none (3000.tunnel.example.com).
// The prefix is the user's ("tunnel" by default); empty means *.<zone> itself.
// A two-level name needs an edge certificate for *.<prefix>.<zone>, which
// Cloudflare's free one isn't (Advanced Certificate Manager is), so the switch
// checks the certificate first (certCovers). naming.certs says who holds the
// certificate for those names:
//   "self"        this machine: a free Let's Encrypt wildcard (edge.mjs), served
//                 by Aegis itself. naming.route says where visitors arrive:
//                 "vps"   your VPS (naming.relay, with Aegis Relay's agent, which
//                         gets a copy of the certificate): the wildcard is a
//                         plain A record to it, always; nothing opens at home
//                 "home"  this machine (the router forwards 443 here, which the
//                         user agreed to do: naming.accept), or naming.relay, the
//                         backup, while it isn't reachable on port 443
//   "relay"       naming.relay alone (Caddy with on-demand TLS, on a server of
//                 yours) fetches a certificate per name, asking
//                 /__gate/relay-ask first, and passes the requests on to this
//                 gate (over a reverse SSH tunnel, say)
//   "worker"      Cloudflare, free and with nothing open at home: every name is a
//                 Custom Domain of one small Worker, which comes with a
//                 certificate for exactly that name (workerfront.mjs); the
//                 Worker hands requests here through the dashboard's tunnel
//   "cloudflare"  Cloudflare's edge (a proxied CNAME), which needs a certificate
//                 that covers two levels (Advanced Certificate Manager) unless
//                 the prefix is empty
//
// More domains (domains.mjs) add names beside those: https://<sub|PORT>.<zone>
// on each other domain whose `tunnels` is "all", or "picked" and listed in
// t.domains. One wildcard record per domain, so nothing is made per tunnel.
// A domain's subdomains add more: a wildcard one (*.apps.<zone>) puts the same
// tunnels at <sub|PORT>.apps.<zone>; a single one (blog.<zone>) is one tunnel's.
//
// Without a domain every tunnel gets its own random *.trycloudflare.com
// address instead (QuickTunnels): no account, but a new name after a restart.
//
// Who may open a tunnel (t.access) is for Aegis to enforce: "login" (the Aegis
// login, the default), "password" (a password of the tunnel's own, t.lock: a
// scrypt hash kept here, never the password), or "public".
//
// A site (t.kind "site", experimental: "secure reverse tunneling") is a
// GitHub or GitLab Pages site served on a subdomain of the user's own, behind
// that password: https://docs.example.com -> https://you.github.io/project/.
// It has no port, so its key is a number above 65535 (70001…), and it is never
// public (a public copy would be the Pages site itself).
//
// Everything a tunnel does is counted here: requests, bytes, status codes,
// latency, WebSockets, and every client that used it.

import { request as httpRequest, Agent as HttpAgent } from "node:http";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { execFile } from "node:child_process";
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { isIP } from "node:net";
import { Edge } from "./edge.mjs";
import { WorkerFront } from "./workerfront.mjs";

const MINUTES = 120;            // per-minute history kept
const SECONDS = 90;             // per-second history for the live chart
const RECENT = 150;             // recent requests kept
const LAT_SAMPLES = 600;        // latency samples for percentiles
const MAX_CLIENTS = 500;        // per tunnel
const HEALTH_EVERY_MS = 15000;
const FAVICON_EVERY_MS = 6 * 3600 * 1000;
// Never HTTP: not worth offering as a tunnel (ssh, smtp, dns, samba, ipp-less extras).
const SUB_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
// {mode: "record" | "wildcard", prefix, certs, relay}: how tunnels on a linked domain are named.
// `saved`: naming from an older version, which had no `certs`. A wildcard
// that needed a relay or a paid certificate then is served by this machine
// now (the relay stays, as the backup); "auto" asks Cloudflare once whether
// its certificate covers the names after all.
const CERTS = new Set(["worker", "self", "relay", "cloudflare"]);
export function cleanNaming(n, { saved = false } = {}) {
  const mode = n?.mode === "wildcard" ? "wildcard" : "record";
  let prefix = n && "prefix" in n ? String(n.prefix ?? "").trim().toLowerCase().replace(/^\*?\.?|\.$/g, "") : "tunnel";
  if (prefix && !prefix.split(".").every((p) => SUB_RE.test(p))) throw new Error("The prefix is letters, digits and dashes, like tunnel (dots for more levels).");
  if (prefix.length > 60) throw new Error("That prefix is too long.");
  const relay = String(n?.relay || "").trim();
  if (relay && !isIP(relay)) throw new Error("The relay is the server's IP address, like 203.0.113.7.");
  let certs = CERTS.has(n?.certs) ? n.certs : null;
  if (!certs) {
    if (saved) certs = mode !== "wildcard" ? "cloudflare" : relay ? "self" : prefix ? "auto" : "cloudflare";
    else certs = relay ? "relay" : "cloudflare";
  }
  if (certs === "relay" && !relay) throw new Error("Name the relay server (its IP), or let this machine hold the certificate.");
  // where visitors arrive while this machine holds the certificate (older saves: home, the relay as the backup)
  const route = certs !== "self" ? null : n?.route === "vps" || n?.route === "home" ? n.route : saved ? "home" : relay ? "vps" : "home";
  if (route === "vps" && !relay) throw new Error("Link your VPS first (its IP address), then the tunnels can move there.");
  return { mode, prefix, certs, relay: relay || null, route };
}
// Cloudflare's free plan: 100,000 Worker requests a day per account (all its
// Workers together), reset at 00:00 UTC. Past it the Worker answers with an error.
export const WORKER_DAILY_LIMIT = 100000;
const NOT_HTTP = new Set([22, 25, 53, 111, 139, 445, 465, 587, 993, 995, 1194, 3306, 5432, 6379, 27017]);

const httpAgent = new HttpAgent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new HttpsAgent({ keepAlive: true, maxSockets: 256, rejectUnauthorized: false });
// a site out on the internet: its certificate is checked
const siteAgent = new HttpsAgent({ keepAlive: true, maxSockets: 64 });

const SITE_BASE = 70000;        // site keys: 70001…99999 (the API takes 1-5 digits)
const SITE_HOST = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?\.(github|gitlab)\.io$/;
const SITE_PATH = /^\/(?:[A-Za-z0-9._~%-]+\/)*$/;
const PASS_MIN = 8;
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export const accessOf = (v) => (v === "public" || v === "password" ? v : "login");
// A tunnel an addon made carries its id (t.app) and a few words about itself
// (t.meta: {repo, branch, mode…}), so the dashboard can show it on that addon's card.
const APP_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
function cleanMeta(app, meta) {
  if (!app || !APP_RE.test(String(app))) return { app: null, meta: null };
  const out = {};
  for (const [k, v] of Object.entries(meta && typeof meta === "object" ? meta : {}).slice(0, 12)) {
    if (/^[a-zA-Z][a-zA-Z0-9]{0,23}$/.test(k) && ["string", "number", "boolean"].includes(typeof v)) out[k] = typeof v === "string" ? v.slice(0, 200) : v;
  }
  return { app: String(app), meta: out };
}

// Where a GitHub or GitLab Pages site really is, from what people paste:
//   github.com/you/project      -> https://you.github.io/project/
//   github.com/you/you.github.io -> https://you.github.io/
//   gitlab.com/group/sub/project -> https://group.gitlab.io/sub/project/
//   you.github.io/project, group.gitlab.io/… as they are
export function parseSite(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("Enter the address of a GitHub or GitLab Pages site.");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch { throw new Error("That doesn't look like an address."); }
  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  const parts = u.pathname.split("/").filter(Boolean);
  const site = (provider, h, path) => {
    const base = path.length ? `/${path.join("/")}/` : "/";
    if (!SITE_HOST.test(h)) throw new Error(`${h} isn't a Pages address Burrow knows.`);
    if (!SITE_PATH.test(base)) throw new Error("That path has characters a Pages site can't have.");
    return { provider, host: h, base, url: `https://${h}${base}` };
  };
  if (host === "github.com" || host === "gitlab.com") {
    const provider = host.split(".")[0];
    // a repository's own path ends where GitHub's /tree/… or GitLab's /-/… starts
    const end = provider === "github" ? Math.min(parts.length, 2) : (parts.indexOf("-") >= 0 ? parts.indexOf("-") : parts.length);
    const [owner, ...rest] = parts.slice(0, end).map((p) => p.replace(/\.git$/i, ""));
    if (!owner) throw new Error(`Add the ${provider === "github" ? "repository" : "project"}, like ${host}/you/project.`);
    const h = `${owner.toLowerCase()}.${provider}.io`;
    return site(provider, h, rest.length === 1 && rest[0].toLowerCase() === h ? [] : rest);
  }
  const m = SITE_HOST.exec(host);
  if (m) return site(m[1], host, parts);
  throw new Error("GitHub and GitLab Pages sites only, for now: you.github.io/project, github.com/you/project, or the GitLab ones.");
}

// A tunnel's own password: Burrow keeps a scrypt hash, Aegis checks it.
export function makeLock(password) {
  const pw = String(password ?? "");
  if (pw.length < PASS_MIN) throw new Error(`A tunnel password is at least ${PASS_MIN} characters.`);
  if (pw.length > 256) throw new Error("That password is too long.");
  const salt = randomBytes(16);
  return { salt: salt.toString("base64url"), hash: scryptSync(pw, salt, 32, SCRYPT).toString("base64url"),
           epoch: randomBytes(6).toString("base64url"), set: Date.now() };
}
export function checkLock(lock, password) {
  if (!lock || typeof password !== "string" || !password || password.length > 256) return false;
  const want = Buffer.from(lock.hash, "base64url");
  return timingSafeEqual(scryptSync(password, Buffer.from(lock.salt, "base64url"), 32, SCRYPT), want);
}

const now = () => Date.now();
const DNS_COMMENT = "aegis (burrow tunnels)";
// Do Cloudflare's and Google's public resolvers both answer for name?
async function publicDnsAnswers(name) {
  const ask = (url) => fetch(url, { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) })
    .then((r) => r.json()).then((j) => j.Status === 0 && (j.Answer || []).length > 0).catch(() => false);
  const q = `?name=${encodeURIComponent(name)}&type=A`;
  const [a, b] = await Promise.all([ask("https://cloudflare-dns.com/dns-query" + q), ask("https://dns.google/resolve" + q)]);
  return a && b;
}
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
  constructor({ dataDir, domain, quick, forbiddenPorts, log, naming, edge, onNaming }) {
    this.dataDir = dataDir;
    try { this.naming = cleanNaming(naming, { saved: true }); } catch { this.naming = cleanNaming(null, { saved: true }); }
    this.onNaming = onNaming || null;       // (naming) => keep it (state.json)
    this.edge = new Edge({ dataDir, log: log || console.log, cfApi: (...a) => this.cfApi(...a), ...(edge || {}) });
    this.edge.onChange = () => this.repointWildcard();
    this.front = new WorkerFront({ file: join(dataDir, "cf", "front.json"), log: log || console.log });
    // requests the Worker handed here today (UTC), against the free plan's daily limit
    this.frontDayFile = join(dataDir, "cf", "worker-today.json");
    this.frontDay = { day: null, n: 0 };
    try { this.frontDay = { ...this.frontDay, ...JSON.parse(readFileSync(this.frontDayFile, "utf8")) }; } catch { /* none yet */ }
    this.quick = quick;                       // QuickTunnels, used while no domain is linked
    this.forbidden = new Set(forbiddenPorts || []);
    this.log = log || console.log;
    this.tunnels = new Map();     // port -> config
    this.live = new Map();        // port -> runtime (stats, clients, recent, sockets, health)
    mkdirSync(join(dataDir, "favicons"), { recursive: true });
    this.extras = [];             // other domains: [{zone, label, picked, root, wilds, fixed}] (domains.mjs)
    this.taken = () => new Set(); // names on a zone with a record of their own
    this.load();
    this.useDomain(domain);
    if (this.naming.certs === "auto") setTimeout(() => this.resolveAuto(), 5000).unref?.();
    this.saveTimer = setInterval(() => { this.save(); this.saveFrontDay(); }, 30000);
    this.healthTimer = setInterval(() => this.healthAll(), HEALTH_EVERY_MS);
    setTimeout(() => this.healthAll(), 1500);
    // records still on their way to public DNS when we last stopped; leftovers
    this.dnsAnswers = publicDnsAnswers;
    this.bootTimer = setTimeout(() => {
      for (const t of this.tunnels.values()) if (t.dns?.ok && t.dns.ready === false) this.watchDns(t.port);
      // a Worker Custom Domain's certificate: checked again (it may have been mistaken for an older record's)
      for (const t of this.tunnels.values()) if (t.dns?.front) { t.dns.ready = false; this.watchFront(t.port); }
      this.sweepDns().catch((e) => this.log("tunnels: DNS sweep failed:", e.message));
    }, 20000).unref?.();
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
    this._wild = null;
    this.syncEdge();
  }
  // The other domains (domains.mjs): which answer for tunnels, and how.
  //   root: tunnels under *.<zone>; wilds: subdomains with a wildcard of their own (the same
  //   tunnels under *.<name>.<zone>); fixed: {name: port}, subdomains that are one tunnel's
  useExtras(list, taken) {
    this.extras = (list || []).map((d) => {
      const subs = Array.isArray(d.subs) ? d.subs : [], root = d.tunnels !== "none";
      return { zone: d.zone.name, label: d.label || "", picked: d.tunnels === "picked", root,
               wilds: root ? subs.filter((x) => x.wildcard).map((x) => x.name) : [], fixed: Object.fromEntries(subs.filter((x) => !x.wildcard).map((x) => [x.name, x.port])) };
    }).filter((d) => d.root || Object.keys(d.fixed).length);
    if (taken) this.taken = taken;
  }
  extraZones() { return this.extras.filter((d) => d.root).map((d) => d.zone); }
  onExtra(t, d) { return d.root && (!d.picked || (t.domains || []).includes(d.zone)); }
  // a tunnel's names on the other domains: [{zone, host, url, hidden?}]
  alsoFor(t) {
    if (!this.domain) return [];
    const out = [];
    for (const d of this.extras) {
      for (const [name, port] of Object.entries(d.fixed)) if (port === t.port) { const host = `${name}.${d.zone}`; out.push({ zone: d.zone, host, url: `https://${host}`, sub: name }); }
      if (!this.onExtra(t, d)) continue;
      const left = t.sub || String(t.port), taken = this.taken(d.zone);
      for (const base of [d.zone, ...d.wilds.map((w) => `${w}.${d.zone}`)]) {
        const host = `${left}.${base}`, root = base === d.zone;
        if (root && d.fixed[left] === t.port) continue;                                          // already there, as its subdomain
        const hidden = root && left === d.label ? "the dashboard's name there" : root && left in d.fixed ? "a subdomain that's another tunnel's"
          : taken.has(host) ? "a DNS record of its own on Cloudflare" : null;
        out.push({ zone: d.zone, host, url: `https://${host}`, ...(root ? {} : { wild: base }), ...(hidden ? { hidden } : {}) });
      }
    }
    return out;
  }
  matchExtra(name) {
    for (const d of this.extras) {
      const suffix = "." + d.zone;
      if (!name.endsWith(suffix)) continue;
      let left = name.slice(0, -suffix.length);
      if (!left || left === d.label) return null;
      if (!left.includes(".")) {
        if (left in d.fixed) return this.tunnels.has(d.fixed[left]) ? d.fixed[left] : null;      // a subdomain that is one tunnel's
      } else {
        const dot = left.indexOf("."), wild = left.slice(dot + 1);                              // NAME.<wildcard subdomain>
        if (!d.wilds.includes(wild)) return null;
        left = left.slice(0, dot);
      }
      let t = null;
      for (const x of this.tunnels.values()) if (x.sub && x.sub === left) t = x;
      if (!t && /^\d{1,5}$/.test(left)) { const x = this.tunnels.get(Number(left)); if (x && !x.sub) t = x; }
      return t && this.onExtra(t, d) ? t.port : null;
    }
    return null;
  }
  get selfCerts() { return this.wildcard && this.naming.certs === "self"; }
  // The edge serves *.<wbase> while this machine holds the certificate.
  syncEdge() {
    this.edge.use(this.selfCerts ? this.wbase : null, this.naming.relay, this.checkName(), this.naming.route);
    // an outside-check record left from when this machine held the certificate (it points at this address): gone
    if (!this.selfCerts && this.domain && !this._checkSwept) { this._checkSwept = true; this.edge.dropCheckRecord({ name: this.checkName() }); }
  }
  // the edge's outside check (edge.mjs): one level under the zone, named after the dashboard
  checkName() { return this.domain ? `edge-check-${this.label}.${this.parent}` : null; }
  get mode() { return this.domain ? "domain" : "quick"; }
  get wildcard() { return !!this.domain && this.naming.mode === "wildcard"; }
  // what the wildcard covers: tunnel.example.com (or example.com with no prefix)
  get wbase() { return this.naming.prefix ? `${this.naming.prefix}.${this.parent}` : this.parent; }
  wildcardName() { return `*.${this.wbase}`; }
  hostFor(port) {
    const sub = this.tunnels.get(Number(port))?.sub;
    if (this.wildcard) return `${sub || Number(port)}.${this.wbase}`;
    if (this.domain) return sub ? `${sub}.${this.parent}` : `tunnel-${port}-${this.label}.${this.parent}`;
    return this.quick?.host(port) || null;
  }
  urlFor(port) { const h = this.hostFor(port); return h ? `https://${h}` : null; }
  pattern() {
    if (this.wildcard) return `NAME.${this.wbase}`;
    return this.domain ? `tunnel-PORT-${this.label}.${this.parent}` : "a random name on trycloudflare.com";
  }
  matchHost(host) {
    const name = String(host || "").toLowerCase().split(":")[0];
    if (this.domain && this.extras.length) { const p = this.matchExtra(name); if (p != null) return p; }
    if (this.wildcard) {
      const suffix = "." + this.wbase;
      if (!name.endsWith(suffix)) return null;
      const left = name.slice(0, -suffix.length);
      if (left.includes(".")) return null;
      for (const t of this.tunnels.values()) if (t.sub && left === t.sub) return t.port;
      return /^\d{1,5}$/.test(left) && this.tunnels.has(Number(left)) && !this.tunnels.get(Number(left)).sub ? Number(left) : null;
    }
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
  // A Workers Custom Domain's own DNS record (AAAA 100::, read-only): Cloudflare
  // makes and removes it with the Custom Domain.
  static isFrontRecord(r) { return r.type === "AAAA" && r.content === "100::" && !!r.meta?.read_only; }
  async checkSub(port, sub, { ignoreFront = false } = {}) {
    if (sub == null || sub === "") return null;
    sub = String(sub).trim().toLowerCase().replace(/\.$/, "");
    if (this.parent && sub.endsWith("." + this.parent)) sub = sub.slice(0, -this.parent.length - 1);
    if (!SUB_RE.test(sub)) throw new Error("A name is 1-40 letters, digits and dashes (not at the ends), like grafana.");
    if (/^tunnel-\d+-/.test(sub)) throw new Error("Names that start with tunnel-PORT- are Burrow's own; pick another.");
    if (/^\d+$/.test(sub)) throw new Error("A name of only digits is how tunnels without a name are reached; add a letter.");
    if (this.domain && sub === this.label && (!this.wildcard || this.wbase === this.parent)) throw new Error("That is the dashboard's own name.");
    for (const t of this.tunnels.values()) if (t.port !== port && t.sub === sub) throw new Error(`tunnel-${t.port} already uses ${sub}.`);
    if (this.wildcard) {
      // a record of its own would win over the wildcard, so the name would never reach us
      const name = `${sub}.${this.wbase}`;
      const recs = (await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`)).filter((r) => !(ignoreFront && TunnelManager.isFrontRecord(r)));
      if (recs.length) throw new Error(`${name} already has a ${recs[0].type} record on Cloudflare, which wins over the wildcard. Pick another name, or delete that record first.`);
    } else if (this.domain) {
      // never take over a record that isn't ours (mail, www, a website…)
      const name = `${sub}.${this.parent}`;
      const recs = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`);
      const other = recs.find((r) => !(r.type === "CNAME" && r.content === `${this.domain.tunnelId}.cfargotunnel.com`));
      if (other) throw new Error(`${name} already has a ${other.type} record on Cloudflare. Pick another name, or delete that record first.`);
    }
    return sub;
  }

  // Is a Pages site really there? (a typo, or Pages switched off, shows up now and not as a 404 later)
  async checkSite(site) {
    let r;
    try { r = await fetch(site.url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000), headers: { "user-agent": "burrow/1 (site check)" } }); }
    catch (e) { throw new Error(`Can't reach ${site.host}: ${e.cause?.code || e.message}.`); }
    if (r.status === 404) throw new Error(`Nothing at ${site.url} (404). Is ${site.provider === "github" ? "GitHub" : "GitLab"} Pages switched on for it?`);
  }

  async create(spec) {
    if (spec.site) return this.createSite(spec);
    const port = Number(spec.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Pick a port from 1 to 65535.");
    if (this.forbidden.has(port)) throw new Error("That is Aegis itself.");
    if (this.tunnels.has(port)) throw new Error(`tunnel-${port} already exists.`);
    const { access, lock } = this.checkAccess(null, spec);
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
      access, lock,
      preserveHost: !!spec.preserveHost,
      enabled: true, created: now(), blocked: [], dns: null,
      ...cleanMeta(spec.app, spec.meta),
    };
    return this.add(t);
  }

  // Secure reverse tunneling: a Pages site on a subdomain of ours, behind a password.
  async createSite(spec) {
    const site = parseSite(spec.site);
    let port = SITE_BASE + 1;
    while (this.tunnels.has(port)) port++;
    if (port > 99999) throw new Error("That's a lot of sites. Remove one first.");
    if (this.domain && !spec.sub) throw new Error("Give the site an address of its own, like docs.");
    const sub = await this.checkSub(port, spec.sub);
    const { access, lock } = this.checkAccess({ kind: "site" }, spec);
    await this.checkSite(site);
    return this.add({
      sub, port, kind: "site", site, targetHost: site.host, targetPort: 443, scheme: "https",
      name: String(spec.name || "").slice(0, 60) || `${site.host}${site.base.slice(0, -1)}`,
      access, lock, preserveHost: false, enabled: true, created: now(), blocked: [], dns: null,
      ...cleanMeta(spec.app, spec.meta),
    });
  }

  async add(t) {
    const port = t.port;
    this.tunnels.set(port, t);
    this.runtime(port);
    this.save();
    await this.publish(port);
    this.save();
    this.refreshFavicon(port, true);
    this.healthOne(port);
    this.log("tunnels: created", port, "->", t.site ? t.site.url : `${t.scheme}://${t.targetHost}:${t.targetPort}`, t.access);
    return this.summary(t);
  }

  // Who may open it, after this change: {access, lock}. Throws before anything changes.
  checkAccess(t, patch) {
    const access = "access" in patch ? accessOf(patch.access) : (t?.access || "login");
    const lock = patch.password ? makeLock(patch.password) : t?.lock || null;
    if (t?.kind === "site" && access === "public") throw new Error("A site behind Burrow is behind a password: the login, or one of its own.");
    if (access === "password" && !lock) throw new Error("Set a password for this tunnel.");
    return { access, lock };
  }

  async update(port, patch) {
    const t = this.get(port);
    if (!t) throw new Error("No such tunnel.");
    if (t.kind === "site" && "sub" in patch && this.domain && !patch.sub) throw new Error("A site needs an address of its own.");
    if ("enabled" in patch) {
      t.enabled = !!patch.enabled;
      if (!t.enabled) this.kick(port, null);
    }
    if ("access" in patch || patch.password) {
      const { access, lock } = this.checkAccess(t, patch);
      if (lock !== t.lock) this.log("tunnels:", t.port, "has a new password; whoever had the old one is out");
      t.access = access; t.lock = lock;
    }
    if ("name" in patch) t.name = String(patch.name || "").slice(0, 60);
    if ("meta" in patch && t.app) t.meta = cleanMeta(t.app, patch.meta).meta;
    if (t.kind === "site") {
      if ("site" in patch) {
        const site = parseSite(patch.site);
        if (site.url !== t.site.url) { await this.checkSite(site); t.site = site; t.targetHost = site.host; this.refreshFavicon(port, true); }
      }
    } else {
    if ("preserveHost" in patch) t.preserveHost = !!patch.preserveHost;
    if ("scheme" in patch && ["http", "https"].includes(patch.scheme)) t.scheme = patch.scheme;
    if ("targetHost" in patch || "targetPort" in patch) {
      if (patch.targetHost) t.targetHost = String(patch.targetHost).trim();
      if (patch.targetPort) t.targetPort = Number(patch.targetPort);
      t.scheme = await this.detectScheme(t.targetHost, t.targetPort);
      this.refreshFavicon(port, true);
    }
    }
    if (patch.block) { if (!t.blocked.includes(patch.block)) t.blocked.push(patch.block); this.kick(port, patch.block); }
    if (patch.unblock) t.blocked = t.blocked.filter((ip) => ip !== patch.unblock);
    if ("domains" in patch) {
      const known = new Set(this.extraZones());
      t.domains = [...new Set((Array.isArray(patch.domains) ? patch.domains : []).map((z) => String(z).toLowerCase()))].filter((z) => known.has(z));
      if (!t.domains.length) delete t.domains;
    }
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
    const host = this.hostFor(t.port);         // its name, while the tunnel (and its sub) still exists
    this.tunnels.delete(t.port);
    this.live.delete(t.port);
    try { if (existsSync(this.file(`favicons/${t.port}`))) unlinkSync(this.file(`favicons/${t.port}`)); } catch { /* ignore */ }
    this.save();
    const dns = await this.unpublish(t.port, host);
    this.log("tunnels: removed", t.port, host || "", "dns", dns);
    return { removed: t.port, dns };
  }

  // Give a tunnel its public name: a DNS record on the linked domain, or a
  // quick tunnel of its own.
  async publish(port) {
    const t = this.get(port);
    if (!t) return;
    if (!this.domain) { t.dns = null; this.quick?.start(port); return; }
    try {
      if (this.frontMode) {
        // a Custom Domain of the Worker, with its own certificate
        const host = this.hostFor(port), { script } = await this.ensureFront();
        await this.front.addDomain(host, script);
        t.dns = { name: host, front: true, ok: true, ready: false };
        this.watchFront(port);
        return;
      }
      if (this.wildcard) {
        // nothing per tunnel: the one wildcard record (made once) answers for it
        const w = await this.ensureWildcard();
        t.dns = { id: w.id, name: this.hostFor(port), wildcard: w.name, ok: true, ...(w.ready ? {} : { ready: false }) };
        if (!w.ready) this.watchDns(port);
        return;
      }
      t.dns = await this.dnsCreate(this.hostFor(port));
      if (t.dns.created) { t.dns.ready = false; delete t.dns.created; this.watchDns(port); }
    } catch (e) {
      t.dns = { error: e.message };
      this.log("tunnels: DNS create failed for", port, e.message);
    }
  }
  async unpublish(port, host) {
    if (!this.domain) { this.quick?.stop(port); return "none"; }
    if (this.frontMode) {
      try { const { account, zone } = this.cf(); this.front.accountId = account; this.front.zoneId = zone; } catch { /* the call below says why */ }
      try { return (await this.front.removeDomain(host || this.hostFor(port))) ? "deleted" : "none"; }
      catch (e) { this.log("tunnels: couldn't remove", host || this.hostFor(port), "from the Worker:", e.message); return "error: " + e.message; }
    }
    if (this.wildcard) return "none";          // the wildcard stays for the others
    try { return await this.dnsDelete(host || this.hostFor(port)); } catch (e) { return "error: " + e.message; }
  }
  get frontMode() { return this.wildcard && this.naming.certs === "worker"; }
  // The Worker, deployed once per run (and again when the dashboard's name changes).
  async ensureFront() {
    const { account, zone } = this.cf();
    this.front.accountId = account; this.front.zoneId = zone;
    if (!this.front.linked) throw new Error("Connect Cloudflare Workers first (Settings → Domain).");
    return this.front.deploy(this.label, this.domain.mainHost);
  }
  // A new Custom Domain's certificate takes a minute or a few: "on its way" till then.
  watchFront(port) {
    const t0 = now();
    const tick = async () => {
      const t = this.get(port);
      if (!t?.dns?.front || t.dns.ready !== false) return;
      if (await this.front.certReady(t.dns.name)) {
        t.dns.ready = true; t.dns.readyAt = now(); this.save();
        this.log("tunnels:", t.dns.name, "has its certificate after", Math.round((now() - t0) / 1000) + "s");
        return;
      }
      if (now() - t0 > 30 * 60e3) { t.dns.ready = true; this.save(); return; }
      setTimeout(tick, 15000).unref?.();
    };
    setTimeout(tick, 5000).unref?.();
  }
  // A new name exists at Cloudflare within seconds, but a browser that asks for
  // it too early is told "no such name" and believes it for up to 30 minutes.
  // So the tunnel says "DNS on its way" until public resolvers answer for it.
  watchDns(port) {
    const t0 = now();
    const tick = async () => {
      const t = this.get(port);
      if (!t?.dns?.ok || t.dns.ready !== false) return;
      const name = t.dns.name;
      if (await this.dnsAnswers(name)) {
        t.dns.ready = true; t.dns.readyAt = now(); this.save();
        if (this._wild && t.dns.wildcard === this._wild.name) this._wild.ready = true;     // the next tunnel needn't wait
        this.log("tunnels:", name, "answers on public DNS after", Math.round((now() - t0) / 1000) + "s");
        return;
      }
      if (now() - t0 > 15 * 60e3) { t.dns.ready = true; this.save(); return; }      // stop asking; it is surely there
      setTimeout(tick, now() - t0 < 60e3 ? 3000 : 15000).unref?.();
    };
    setTimeout(tick, 1500).unref?.();
  }
  // Records Burrow made whose tunnel is gone (removed by an older version that
  // looked for the wrong name): take them down.
  async sweepDns() {
    if (!this.domain) return;
    const content = `${this.domain.tunnelId}.cfargotunnel.com`;
    const mine = this.frontMode ? new Set() : this.wildcard ? new Set([this.wildcardName()]) : new Set([...this.tunnels.keys()].map((p) => this.hostFor(p)));
    const recs = [...await this.cfApi("GET", "/dns_records?type=CNAME&per_page=1000"),
                  ...(await this.cfApi("GET", "/dns_records?type=A&per_page=1000")).filter((r) => r.type === "A" && r.comment === DNS_COMMENT),
                  ...(await this.cfApi("GET", "/dns_records?type=AAAA&per_page=1000")).filter((r) => r.type === "AAAA" && r.comment === DNS_COMMENT)];
    for (const r of recs) {
      const relayRec = r.type === "A" || r.type === "AAAA";
      if ((!relayRec && r.content !== content) || r.comment !== DNS_COMMENT || mine.has(r.name) || r.name === this.domain.mainHost) continue;
      await this.cfApi("DELETE", `/dns_records/${r.id}`);
      this.log("tunnels: removed a leftover DNS record:", r.name);
    }
  }

  // ------------------------------------------------------------- one wildcard record
  // The one wildcard record for every tunnel. {id, name, content, ready}
  wildTarget() {
    const ip = (a) => ({ type: isIP(a) === 6 ? "AAAA" : "A", content: a, proxied: false });
    if (this.naming.certs === "self") {
      const t = this.edge.target();
      if (!t) throw new Error("Waiting for this machine's public address.");
      return ip(t.ip);
    }
    if (this.naming.certs === "relay") return ip(this.naming.relay);
    return { type: "CNAME", content: `${this.domain.tunnelId}.cfargotunnel.com`, proxied: true };
  }
  async ensureWildcard() {
    const name = this.wildcardName(), want = this.wildTarget();
    if (this._wild?.name === name && this._wild.content === want.content) return this._wild;
    const rec = await this.dnsUpsert(name, want);
    this._wild = { id: rec.id, name, content: want.content, ready: !rec.created };
    if (rec.created) this.log("tunnels: one wildcard record now serves every tunnel:", name);
    return this._wild;
  }
  // The edge says the record should point elsewhere (this machine <-> the backup relay).
  async repointWildcard() {
    if (!this.selfCerts || !this.domain) return;
    try {
      const before = this._wild?.content;
      const w = await this.ensureWildcard();
      if (before !== w.content) this.log(`tunnels: ${w.name} points at ${w.content}`);
      for (const t of this.tunnels.values()) if (t.dns?.wildcard) t.dns = { id: w.id, name: t.dns.name, wildcard: w.name, ok: true };
    } catch (e) { this.log("tunnels: couldn't move the wildcard record:", e.message); }
  }
  // An older install's two-level wildcard: does Cloudflare's certificate cover
  // it (Advanced Certificate Manager)? Then it stays there; if not, this
  // machine takes over.
  async resolveAuto() {
    if (this.naming.certs !== "auto") return;
    const covered = this.domain && this.wildcard ? await this.certCovers(`burrow-check.${this.wbase}`).catch(() => false) : true;
    this.naming = { ...this.naming, certs: covered ? "cloudflare" : "self" };
    if (this.wildcard) this.log("tunnels:", covered ? "Cloudflare's certificate covers" : "this machine holds the certificate for", this.wildcardName());
    this.onNaming?.(this.naming);
    this.syncEdge();
    if (!covered) this.edge.ensureCert().then(() => this.repointWildcard()).catch(() => { /* edge.error says why */ });
  }
  // Does Cloudflare's edge hold a certificate for `host`? Asks the edge itself
  // (through the dashboard's own name, which is surely proxied there).
  certCovers(host) {
    return new Promise((resolve) => {
      const sock = tlsConnect({ host: this.domain.mainHost, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
        const sans = String(sock.getPeerCertificate()?.subjectaltname || "").split(/,\s*/).map((s) => s.replace(/^DNS:/, "").toLowerCase());
        sock.destroy();
        resolve(sans.some((n) => n === host || (n.startsWith("*.") && host.endsWith(n.slice(1)) && !host.slice(0, -n.length + 1).includes("."))));
      });
      sock.on("error", () => resolve(false));
      sock.on("timeout", () => { sock.destroy(); resolve(false); });
    });
  }
  // One request through the Worker (aegis/server.mjs counts them as they arrive).
  countFront() {
    const d = new Date().toISOString().slice(0, 10);
    if (this.frontDay.day !== d) this.frontDay = { day: d, n: 0 };
    this.frontDay.n++;
    this.frontDayDirty = true;
  }
  frontToday() {
    const d = new Date().toISOString().slice(0, 10);
    const n = this.frontDay.day === d ? this.frontDay.n : 0;
    const reset = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate() + 1);
    return { day: d, n, limit: WORKER_DAILY_LIMIT, reset };
  }
  saveFrontDay() {
    if (!this.frontDayDirty) return;
    this.frontDayDirty = false;
    try { mkdirSync(join(this.dataDir, "cf"), { recursive: true }); writeFileSync(this.frontDayFile, JSON.stringify(this.frontDay)); } catch { /* next time */ }
  }
  namingInfo() {
    return { ...this.naming, active: this.wildcard, zone: this.parent, label: this.label,
             example: this.domain ? (this.naming.mode === "wildcard" ? `radio.${this.wbase}` : `tunnel-3000-${this.label}.${this.parent}`) : null,
             record: this.wildcard ? this.wildcardName() : null, relay: this.naming.relay,
             edge: this.selfCerts ? this.edge.state() : null,
             front: { linked: this.front.linked, script: this.front.deployed?.script || null, error: this.front.error,
                      today: this.frontMode ? this.frontToday() : null } };
  }
  // The relay's question before it fetches a certificate: is this one of ours?
  // (The backup relay asks too: it serves the names while this machine can't.)
  relayAsk(host) {
    if (!this.wildcard || !this.naming.relay || this.naming.certs === "cloudflare" || this.naming.certs === "worker") return false;
    const port = this.matchHost(host);
    return port !== null && !!this.get(port)?.enabled;
  }
  // Switch between a record per tunnel and one wildcard (or change the prefix).
  // Every tunnel moves to its new name; the records of the old way go.
  async setNaming(next, { force = false } = {}) {
    const naming = cleanNaming(next);
    if (!this.domain) throw new Error("Link a domain first: without one, tunnels get trycloudflare.com names.");
    if (naming.mode === "wildcard") {
      const base = naming.prefix ? `${naming.prefix}.${this.parent}` : this.parent;
      if (naming.certs === "cloudflare" && !force && !(await this.certCovers(`burrow-check.${base}`))) {
        const e = new Error(`Cloudflare's certificate for ${this.parent} doesn't cover *.${base}, so browsers would refuse those addresses. ` +
          `Let this machine hold the certificate instead (free, from Let's Encrypt), order one from Cloudflare (Advanced Certificate Manager, paid), or leave the prefix empty to use *.${this.parent}, which the free certificate covers.`);
        e.code = "cert";
        throw e;
      }
      if (naming.certs === "self") {
        // this machine takes the visitors only once the user has agreed to forward port 443 to it
        const wasHome = this.wildcard && this.naming.certs === "self" && this.naming.route === "home";
        if (naming.route === "home" && !wasHome && next?.accept !== true) {
          const e = new Error("This machine only works with TCP port 443 forwarded to it on your router, which Aegis won't do for you. Confirm that you'll set it up (and what it means), or use your VPS.");
          e.code = "accept";
          throw e;
        }
        // the certificate first: nothing moves unless it came
        this.edge.use(base, naming.relay, this.checkName(), naming.route);
        try {
          await this.edge.ensureCert({ force: true });
          if (naming.route === "home") {
            await this.edge.refreshIp();
            await this.edge.check();
            if (!this.edge.target()) throw new Error("Couldn't find this machine's public address.");
          }
        } catch (e) {
          this.syncEdge();
          const err = new Error(`No certificate for *.${base}: ${e.message}`);
          err.code = "acme";
          throw err;
        }
        // the VPS gets linked, checked and handed the certificate before the record moves there
        if (naming.route === "vps" && this.beforeVps) {
          try { await this.beforeVps(naming); }
          catch (e) { this.syncEdge(); const err = new Error(e.message); err.code = "relay"; throw err; }
        }
      }
    }
    if (naming.mode === "wildcard" && naming.certs === "worker") {
      try {
        const { account, zone } = this.cf();
        this.front.accountId = account; this.front.zoneId = zone;
        if (!this.front.linked) throw new Error("connect Cloudflare Workers first.");
        await this.front.deploy(this.label, this.domain.mainHost);
      } catch (e) { const err = new Error(`The Worker isn't ready: ${e.message}`); err.code = "front"; throw err; }
    }
    const before = { ...this.naming };
    const leavingFront = this.frontMode && !(naming.mode === "wildcard" && naming.certs === "worker");
    // check every name against the new way first: nothing changes unless all of them can move
    // (the Worker's own records don't count: they go with its Custom Domains, below)
    this.naming = naming;
    try {
      if (this.wildcard) for (const t of this.tunnels.values()) {
        if (!t.sub) continue;
        try { await this.checkSub(t.port, t.sub, { ignoreFront: leavingFront }); } catch (e) { throw new Error(`${t.sub} (tunnel-${t.port}): ${e.message}`); }
      }
    } catch (e) { this.naming = before; this.syncEdge(); throw e; }
    this.naming = before;
    if (leavingFront) {
      // the Worker's Custom Domains go, every one (old names too): their records would shadow the new way
      let gone;
      try {
        // which account and zone: only set when the Worker was deployed in this run (accounts/null otherwise)
        const { account, zone } = this.cf();
        this.front.accountId = account; this.front.zoneId = zone;
        gone = await this.front.removeAll();
      }
      catch (e) {
        this.syncEdge();
        for (const port of this.tunnels.keys()) await this.publish(port);          // put back what did go
        throw new Error(`Couldn't remove the Worker's names from Cloudflare (${e.message}); nothing was moved.`);
      }
      if (gone.length) this.log("tunnels: removed the Worker's names:", gone.join(", "));
      // Cloudflare drops their records a moment later: wait for that, so the wildcard isn't shadowed
      for (let i = 0; i < 45; i++) {
        const left = (await this.cfApi("GET", "/dns_records?type=AAAA&per_page=1000")).filter((r) => TunnelManager.isFrontRecord(r) && gone.includes(r.name));
        if (!left.length) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    this.naming = naming;
    this._wild = null;
    this.syncEdge();
    for (const port of this.tunnels.keys()) { const t = this.get(port); t.dns = null; await this.publish(port); }
    this.save();
    this.onNaming?.(this.naming);
    await this.sweepDns().catch((e) => this.log("tunnels: DNS sweep failed:", e.message));
    this.log("tunnels: addresses are now", this.pattern());
    return this.namingInfo();
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
      kind: t.kind || "port", site: t.site ? { provider: t.site.provider, url: t.site.url } : null,
      target: t.site ? t.site.url : `${t.scheme}://${t.targetHost}:${t.targetPort}`, targetHost: t.targetHost, targetPort: t.targetPort,
      scheme: t.scheme, name: t.name, sub: t.sub || null, title: rt.title, access: t.access, preserveHost: t.preserveHost,
      locked: !!t.lock, lockSet: t.lock?.set || null, app: t.app || null, meta: t.meta || null,
      enabled: t.enabled, created: t.created, blocked: t.blocked, dns: t.dns,
      also: this.alsoFor(t), domains: t.domains || [], pickable: this.domain ? this.extras.filter((d) => d.picked).map((d) => d.zone) : [],
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

  // A site's path: its pages live under base (/project/), ours start at /.
  // Absolute links the site makes itself (/project/x) are kept as they are.
  sitePath(t, p) {
    const base = t.site.base;
    if (base === "/" || p === base.slice(0, -1) || p.startsWith(base) || p.startsWith(base.slice(0, -1) + "?")) return p;
    return base + p.replace(/^\//, "");
  }
  // ...and the way back, for a redirect: https://you.github.io/project/x -> /x
  siteLocation(t, loc) {
    try {
      const u = new URL(loc, `https://${t.site.host}/`);
      if (u.hostname !== t.site.host) return loc;
      let p = u.pathname;
      if (t.site.base !== "/" && (p + "/").startsWith(t.site.base)) p = "/" + p.slice(t.site.base.length);
      return p + u.search + u.hash;
    } catch { return loc; }
  }
  siteHeaders(t, req) {
    const h = {};
    // nothing about the visitor or Cloudflare goes on to GitHub or GitLab
    for (const [k, v] of Object.entries(req.headers)) if (!/^(cf-|x-forwarded-|x-real-ip$|true-client-ip$|cdn-loop$)/i.test(k)) h[k] = v;
    h.host = t.site.host;
    const pub = `https://${String(req.headers.host || "").toLowerCase()}`, up = `https://${t.site.host}`;
    if (h.origin && h.origin.toLowerCase() === pub) h.origin = up;
    if (h.referer && (h.referer.toLowerCase() + "/").startsWith(pub + "/")) h.referer = up + this.sitePath(t, h.referer.slice(pub.length) || "/");
    return h;
  }

  upstreamHeaders(t, req, extra) {
    if (t.kind === "site") return this.siteHeaders(t, req);
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
    const site = t.kind === "site";
    const mod = t.scheme === "https" ? httpsRequest : httpRequest;
    const up = mod({ host: t.targetHost, port: t.targetPort, method: req.method, path: site ? this.sitePath(t, req.url) : req.url, headers,
                     agent: site ? siteAgent : t.scheme === "https" ? httpsAgent : httpAgent, timeout: 120000 }, (upRes) => {
      status = upRes.statusCode;
      const out = { ...upRes.headers };
      if (site && out.location) out.location = this.siteLocation(t, out.location);
      res.writeHead(upRes.statusCode, out);
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
    if (t.kind === "site") { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }   // Pages sites have no WebSockets
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
      const site = t.kind === "site";
      const req = mod({ host: t.targetHost, port: t.targetPort, path: site ? this.sitePath(t, path) : path, method: "GET", timeout: 5000,
                        rejectUnauthorized: site, agent: site ? siteAgent : undefined,
                        headers: { host: site ? t.site.host : (t.preserveHost && this.hostFor(t.port)) || `${t.targetHost}:${t.targetPort}`,
                                   "user-agent": "aegis/1 (favicon)", accept: "*/*" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && limit > 0) {
          res.resume();
          try {
            const u = new URL(site ? this.siteLocation(t, res.headers.location) : res.headers.location, `${t.scheme}://${t.targetHost}:${t.targetPort}${path}`);
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
    this._cf = { zone: d.zoneID, token: d.apiToken, account: d.accountID };
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
  // The zone's records, read-only (what an addon may look at: Burrow Pages
  // checks whether the domain already points at GitHub or GitLab Pages).
  async dnsRecords() {
    if (!this.domain) return [];
    const recs = await this.cfApi("GET", "/dns_records?per_page=1000");
    return recs.map(({ name, type, content, proxied, comment }) => ({ name, type, content, proxied: !!proxied, comment: comment || "" }));
  }
  // A record of ours, made or put right: {id, name, ok, created?}
  async dnsUpsert(name, { type, content, proxied }) {
    const existing = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`);
    const rec = existing.find((r) => r.name === name);
    const body = { type, name, content, proxied, ttl: 1, comment: DNS_COMMENT };
    if (rec && rec.type === type && rec.content === content && !!rec.proxied === proxied) return { id: rec.id, name, ok: true };
    if (rec) {
      if (rec.comment !== DNS_COMMENT && !(rec.type === "CNAME" && rec.content === `${this.domain.tunnelId}.cfargotunnel.com`)) {
        throw new Error(`${name} already has a ${rec.type} record that isn't Burrow's.`);
      }
      if (rec.type !== type) { await this.cfApi("DELETE", `/dns_records/${rec.id}`); }
      else { const r = await this.cfApi("PUT", `/dns_records/${rec.id}`, body); return { id: r.id, name, ok: true }; }
    }
    const r = await this.cfApi("POST", "/dns_records", body);
    return { id: r.id, name, ok: true, created: true };
  }
  async dnsCreate(name) {
    const content = `${this.domain.tunnelId}.cfargotunnel.com`;
    const existing = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`);
    const rec = existing.find((r) => r.name === name);
    if (rec && rec.type === "CNAME" && rec.content === content && rec.proxied) return { id: rec.id, name, ok: true };
    if (rec) {
      const r = await this.cfApi("PUT", `/dns_records/${rec.id}`, { type: "CNAME", name, content, proxied: true, ttl: 1, comment: DNS_COMMENT });
      return { id: r.id, name, ok: true };
    }
    const r = await this.cfApi("POST", "/dns_records", { type: "CNAME", name, content, proxied: true, ttl: 1, comment: DNS_COMMENT });
    return { id: r.id, name, ok: true, created: true };
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

  stop() { clearInterval(this.saveTimer); clearInterval(this.healthTimer); clearTimeout(this.bootTimer); this.edge.stop(); this.quick?.stopAll(); this.save(); }
}
