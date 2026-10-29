// Aegis × Burrow, the Aegis half: the gate and every page. One post-quantum
// login in front of your apps (Termix, Selkies Forge, anything with a URL) and
// of Burrow (../burrow), the tunnel engine underneath, which can be switched
// off.
//
// Nothing reaches a protected page, Termix or a login-protected tunnel until
// this server has seen a valid sign-in. The credentials are sealed in the
// browser with two nested AES-256-GCM layers whose keys come from a fresh
// post-quantum hybrid KEM (X-Wing: ML-KEM-768 + X25519):
//
//   ss          = X-Wing shared secret (server keypair is single-use, one per sign-in)
//   K_inner     = HKDF-SHA384(ss, salt=challengeId, "aegis/v1/inner")
//   K_outer     = HKDF-SHA384(ss, salt=challengeId, "aegis/v1/outer")
//   payload     = AES-256-GCM(K_outer, AES-256-GCM(K_inner, credentials))
//
// so neither Cloudflare nor anything between the browser and this process can
// read them, even over plain HTTP on a LAN. With `tls` set, the server itself
// speaks TLS 1.3 with the X25519MLKEM768 key exchange and AES-256-GCM only.
// The session cookie is an AES-256-GCM sealed token bound to the host it was
// issued for.
//
// One sign-in per browser: with a linked domain, a "login" tunnel host
// without a session bounces to the dashboard's /__gate/sso, which (if signed
// in) hands back a single-use, 60 s ticket bound to that tunnel host. Every
// session carries the dashboard login's sid, so signing out there revokes the
// tunnel sessions it spawned too.
//
// Hosts:
//   <dashboard>                         sign in -> home -> Termix | Tunnels | Settings
//   tunnel-<PORT>-<label>.<zone>        a tunnel (tunnels.mjs), domain mode
//   <random>.trycloudflare.com          a tunnel, quick mode (no domain)
// The dashboard answers on the linked domain's name and on local names
// (localhost, IP addresses, single-label and .local names, extraHosts).

import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, appendFileSync, statSync, rmSync, readdirSync,
         linkSync, symlinkSync, readlinkSync, copyFileSync } from "node:fs";
import { join, extname } from "node:path";
import { pathToFileURL } from "node:url";
import { networkInterfaces, tmpdir } from "node:os";
import { webcrypto, randomBytes, randomUUID, scryptSync, timingSafeEqual,
         createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { ml_kem768_x25519 as xwing } from "./vendor/pq.mjs";
import { APP, HOME, DATA, VERSION, Settings, writeJson } from "./config.mjs";
import { Devices, DEVICE_TTL_S } from "./devices.mjs";
import { Burrow } from "../burrow/index.mjs";
import { CHECK_PATH } from "../burrow/edge.mjs";
import { readProxyHeader } from "../burrow/proxyproto.mjs";
import { createServer as createNetServer, connect as netConnect, isIP } from "node:net";
import { RelayLink, AGENT_VERSION, visitorPage, verify as relayVerify } from "../burrow/relaylink.mjs";
import { lookup as dnsLookup } from "node:dns/promises";
import { checkLock, cleanNaming } from "../burrow/tunnels.mjs";
import { Serveo } from "../burrow/serveo.mjs";
import { Addons, AddonError, RootError } from "../burrow/addons.mjs";
import { Standby } from "../burrow/standby.mjs";
import { RelayDoctor } from "../burrow/relaydoctor.mjs";
import { health as bridgeHealth, submitToForge, adoptForge, forgeJob, forgeHasUs } from "./bridge.mjs";
import { Termix } from "./termix.mjs";
import { Fleet, isUp as machineUp, FleetError, termixQuery } from "./fleet.mjs";
import { AgentHub } from "./fleet-agent.mjs";
import { CATALOG as FLEET_APPS, install as fleetInstall, swap as fleetSwap, transfer as fleetTransfer, moveGate as fleetMoveGate, toTermix,
         standbyOn, standbyOff, standbyRefresh, takeover, takeoverNotice } from "./fleet-ops.mjs";
import { Pack } from "./pack.mjs";
import { Updater } from "./updater.mjs";
import { listIntegrations, getIntegration, publicView, forgeDesktops, forgeAction, addonView } from "./integrations.mjs";

const settings = new Settings();
const LISTEN = { host: "127.0.0.1", port: 4310, ...settings.get("listen") };
if (process.env.AEGIS_PORT) LISTEN.port = Number(process.env.AEGIS_PORT);
if (process.env.AEGIS_BIND) LISTEN.host = process.env.AEGIS_BIND;
const TLS = settings.get("tls");
const COOKIE = settings.get("cookie") || "__Host-aegis";          // also the AEAD label of the token
const PLAIN_COOKIE = "aegis";                                      // the same token on plain HTTP
const GO = "aegis-go";                                             // one-shot: "the next / is Termix"
const DEVICE = "aegis-dev";                                         // the device key (aegis/devices.mjs; AEAD label too)
const UNLOCK = "aegis-unlock";                                     // a tunnel's own password was entered (AEAD label too)
const CLONE = "aegis-clone";                                       // a clone key: another gate had the password (AEAD label)
// Configurable under Settings → Sign-in (data/state.json).
const sessionTtl = () => Math.max(1, Math.min(365, Number(settings.get("sessionDays")) || 30)) * 864e5;
const SESSION_RENEW_MS = 24 * 60 * 60 * 1000;
const TICKET_TTL_MS = 60 * 1000;
const SETUP_WINDOW_MS = 30 * 60 * 1000;
const REVOKED_FILE = join(DATA, "revoked.json");
const CHALLENGE_TTL_MS = 2 * 60 * 1000;

// This gate moved to another machine (Machines → Move this gate): nothing
// else starts here, only a notice on the old address (aegis/moved.mjs).
if (settings.get("moved")) {
  const { serveMoved } = await import("./moved.mjs");
  serveMoved({ moved: settings.get("moved"), listen: LISTEN, tls: TLS, tlsOptions: () => tlsOptions(), log: (...a) => console.log(new Date().toISOString(), ...a) });
  await new Promise(() => {});
}
const lockout = () => {
  const l = settings.get("lockout") || {};
  return { fails: Math.max(3, Math.min(50, Number(l.attempts) || 5)), windowMs: Math.max(1, Math.min(1440, Number(l.minutes) || 15)) * 60000 };
};

function log(...args) { console.log(new Date().toISOString(), ...args); }
// your devices (aegis/devices.mjs): which browser a request comes from, for sure (its device key)
const devices = new Devices({ file: join(DATA, "devices.json"), log });

// ---------- the audit log ----------
// Who did what, kept apart from the noise: every sign-in (and failed one), sign-out,
// password change, tunnel change from the dashboard, Termix opened and every Termix
// terminal connection, and requests for Termix turned away for want of a sign-in.
// data/audit.log, one JSON object per line (mode 600), rolled over at 5 MB; also in
// the journal as "audit: ...". `aegis audit` and Settings → Activity show it.
const AUDIT_FILE = () => join(DATA, "audit.log");
const auditQuiet = new Map();          // "event|ip" -> last time (events that can flood)
function audit(event, req, extra = {}) {
  const ip = req ? clientIp(req) : "local";
  if (extra.quiet) {
    const k = `${event}|${ip}`, last = auditQuiet.get(k) || 0;
    if (Date.now() - last < 60000) return;
    auditQuiet.set(k, Date.now());
    if (auditQuiet.size > 5000) auditQuiet.clear();
    delete extra.quiet;
  }
  const e = { t: new Date().toISOString(), event, ip,
              ...(req ? { host: hostOf(req), ua: String(req.headers["user-agent"] || "").slice(0, 200) } : {}),
              ...(req && sessionOf(req) ? { sid: String(sessionOf(req).sid).slice(0, 8) } : {}), ...extra };
  log("audit:", event, ip, ...Object.entries(extra).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`));
  try {
    const f = AUDIT_FILE();
    try { if (statSync(f).size > 5 * 1024 * 1024) renameSync(f, f + ".1"); } catch { /* none yet */ }
    appendFileSync(f, JSON.stringify(e) + "\n", { mode: 0o600 });
  } catch (err) { log("audit: couldn't write", err.message); }
}
// ---------- notices: warnings addons (and Aegis) put on the dashboard ----------
// data/notices.json, newest first (200 kept). An addon calls ctx.notify({level,
// title, body, link, key, items}); items are a list ({label, cc, sub, tag, link},
// 60 kept). The same key while still unread grows that notice instead of adding
// another: new items go on top of the old ones (never instead of them), and a
// title like "Bulwark banned {n} {address|addresses}" counts them. The bell in the top bar lists
// them; an unread critical one also shows as a banner on every page.
const NOTICES_FILE = () => join(DATA, "notices.json");
const NOTICE_LEVELS = new Set(["info", "warn", "critical"]);
let noticesCache = null;
const noticeRate = new Map();          // source -> [times in the last hour]
function noticesLoad() {
  if (!noticesCache) { try { noticesCache = JSON.parse(readFileSync(NOTICES_FILE(), "utf8")); } catch { noticesCache = []; } }
  return noticesCache;
}
function noticesSave() {
  try { writeFileSync(NOTICES_FILE() + ".tmp", JSON.stringify(noticesCache.slice(0, 200)), { mode: 0o600 }); renameSync(NOTICES_FILE() + ".tmp", NOTICES_FILE()); }
  catch (e) { log("notices: couldn't save", e.message); }
}
const noticeLink = (l) => typeof l === "string" && /^\/__gate\/[\w\-./?=&#%:]*$/.test(l) ? l : null;     // only the dashboard's own pages
const noticeItems = (items) => (Array.isArray(items) ? items : []).slice(0, 60).map((i) => ({
  label: String(i?.label || "").slice(0, 80), cc: /^[A-Z]{2}$/.test(i?.cc || "") ? i.cc : "", sub: String(i?.sub || "").slice(0, 200),
  tag: String(i?.tag || "").slice(0, 24), link: noticeLink(i?.link), t: Number(i?.t) || Date.now() })).filter((i) => i.label);
// "Bulwark banned {n} {address|addresses}" -> "Bulwark banned 3 addresses"
const noticeTitle = (tpl, n) => tpl.replace(/\{n\}/g, String(n)).replace(/\{([^|{}]*)\|([^|{}]*)\}/g, (_, one, many) => (n === 1 ? one : many));
function notify(source, n = {}) {
  const level = NOTICE_LEVELS.has(n.level) ? n.level : "info";
  const tpl = String(n.title || "").trim().slice(0, 160);
  if (!tpl) throw new Error("A notice needs a title.");
  const body = String(n.body || "").slice(0, 1200), key = n.key ? String(n.key).slice(0, 120) : null;
  const link = noticeLink(n.link), items = noticeItems(n.items);
  const list = noticesLoad(), now = Date.now();
  const same = key && list.find((x) => x.source === source && x.key === key && !x.read);
  if (same) {
    const fresh = new Set(items.map((i) => i.label));
    const merged = [...items, ...(same.items || []).filter((i) => !fresh.has(i.label))].slice(0, 60);
    const total = (same.total || (same.items || []).length || 1) + items.filter((i) => !(same.items || []).some((o) => o.label === i.label)).length;
    Object.assign(same, { t: now, level: level === "critical" || same.level !== "critical" ? level : same.level, tpl, title: noticeTitle(tpl, items.length ? total : (same.count || 1) + 1),
                          body: body || same.body, link: link || same.link, items: merged, total: items.length ? total : same.total, count: (same.count || 1) + 1 });
  } else {
    const times = (noticeRate.get(source) || []).filter((t) => now - t < 3600e3);
    if (times.length >= 30) return null;                                      // an addon gone wild: the bell isn't a log
    times.push(now); noticeRate.set(source, times);
    const title = noticeTitle(tpl, items.length || 1);
    list.unshift({ id: randomBytes(6).toString("hex"), t: now, first: now, source, level, tpl, title, body, link, key, items, total: items.length, read: false, count: 1 });
    log(`notice: [${level}] ${source}: ${title}`);
  }
  noticesSave();
  return same?.id || list[0].id;
}
// One bad request (here, or in an addon running inside us: Burrow Pages, Bulwark…) must
// not stop every service behind the gate. An error nothing caught is logged and put on
// the bell, and the gate keeps going. Startup errors (a port taken) and a storm of them
// (over 20 in a minute) still end the process, so the service manager starts it clean.
const startedClean = Date.now();
let crashTimes = [];
function survived(kind, e) {
  const now = Date.now();
  crashTimes = crashTimes.filter((t) => now - t < 60000).concat(now);
  log(`${kind}: ${e?.stack || e}`);
  if (now - startedClean < 15000 || ["EADDRINUSE", "EACCES", "EADDRNOTAVAIL"].includes(e?.code) || crashTimes.length > 20) {
    log(crashTimes.length > 20 ? "too many errors in a minute: restarting clean" : "an error while starting: stopping");
    process.exit(1);
  }
  try {
    notify("aegis", { level: "warn", key: "uncaught", title: "Aegis caught an error that would have stopped it",
                      body: `${String(e?.message || e).slice(0, 300)}${/\/addons\/([a-z0-9-]+)\//.exec(e?.stack || "") ? ` (in the ${/\/addons\/([a-z0-9-]+)\//.exec(e.stack)[1]} addon)` : ""}. Everything kept running.` });
  } catch { /* the bell is a nicety */ }
}
process.on("unhandledRejection", (e) => survived("unhandled rejection", e));
process.on("uncaughtException", (e) => survived("uncaught exception", e));

function noticesView() {
  const list = noticesLoad();
  const unread = list.filter((x) => !x.read);
  const top = unread.find((x) => x.level === "critical") || null;
  return { unread: unread.length, worst: unread.some((x) => x.level === "critical") ? "critical" : unread.some((x) => x.level === "warn") ? "warn" : unread.length ? "info" : null,
           banner: top ? { id: top.id, source: top.source, title: top.title, body: top.body, link: top.link, t: top.t, count: top.count, items: (top.items || []).slice(0, 4), total: top.total || 0 } : null };
}

function auditRead(n = 200) {
  try {
    const lines = readFileSync(AUDIT_FILE(), "utf8").trim().split("\n").slice(-Math.min(2000, n));
    return lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();
  } catch { return []; }
}

function loadKey() {
  const p = join(HOME, "secret.key");
  if (!existsSync(p)) { mkdirSync(HOME, { recursive: true }); writeFileSync(p, randomBytes(32), { mode: 0o600 }); }
  const k = readFileSync(p);
  if (k.length !== 32) throw new Error(`${p} must hold exactly 32 bytes`);
  return k;
}
const SESSION_KEY = loadKey();

const PUBLIC = join(APP, "public");
const FILES = {};
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
for (const f of ["login.html", "setup.html", "unlock.html", "home.html", "tunnels.html", "settings.html", "welcome.html",
                 "login.js", "common.js", "home.js", "tunnels.js", "settings.js", "welcome.js", "distros.js", "fleet.js", "ui.css", "login.css",
                 "logos/aegis.svg", "logos/aegis-burrow.svg", "logos/burrow.svg", "logos/termix.svg", "logos/forge.svg", "logos/weft.svg", "logos/burrow-pages.svg", "logos/bulwark.svg"]) {
  FILES[f] = readFileSync(join(PUBLIC, f));
}
// Every link to our scripts and styles carries the version: a proxy in front
// (Cloudflare's Browser Cache TTL turns no-cache into max-age=14400) can't keep
// an old copy around after an update, because the new pages ask for new URLs.
for (const f of Object.keys(FILES)) {
  if (!/\.(html|js)$/.test(f)) continue;
  FILES[f] = Buffer.from(FILES[f].toString("utf8")
    .replace(/(["'(])(\/__gate\/[a-z-]+\.(?:js|css))(["')])/g, `$1$2?v=${VERSION}$3`)
    .replace(/(from\s+["']\.\/[a-z-]+\.js)(["'])/g, `$1?v=${VERSION}$2`));
}
const TYPES = { ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".html": "text/html; charset=utf-8" };

// ---------- the pieces ----------

// Where cloudflared (on this machine) reaches us: the listen address itself,
// or loopback when we listen on every address.
const ORIGIN_HOST = ["0.0.0.0", "::", ""].includes(LISTEN.host) ? "127.0.0.1"
  : LISTEN.host.includes(":") ? `[${LISTEN.host}]` : LISTEN.host;
const origin = () => ({ url: `${TLS ? "https" : "http"}://${ORIGIN_HOST}:${LISTEN.port}`, insecure: !!TLS });
// The edge: wildcard tunnels on this machine's own certificate (burrow/edge.mjs),
// on a public port of their own: 443 when this process may listen there
// (root, or CAP_NET_BIND_SERVICE), else 8443, else 18443, unless config.json
// says {edge: {port}}. The router forwards 443 here.
const EDGE = { host: "0.0.0.0", upnp: true, ...settings.get("edge") };
if (process.env.AEGIS_EDGE_PORT) EDGE.port = Number(process.env.AEGIS_EDGE_PORT);
const EDGE_PORTS = EDGE.port ? [Number(EDGE.port)] : [443, 8443, 18443];
const burrow = new Burrow({ settings, dataDir: DATA, home: HOME, origin, forbiddenPorts: [LISTEN.port, ...EDGE_PORTS], log, version: VERSION,
                            edge: { port: EDGE_PORTS[0], upnp: EDGE.upnp } });
const { tunnels, cloudflare } = burrow;
// the shield (burrow/shield.mjs): its lists, and the addresses you signed in from
if (process.env.AEGIS_SHIELD_OFFLINE !== "1") burrow.shield.start();
setTimeout(() => {
  const since = Date.now() - 30 * 86400e3;
  for (const e of auditRead(2000)) if (e.event === "sign-in" && Date.parse(e.t) > since && !burrow.shield.isTrusted(e.ip)) burrow.shield.trust(e.ip);
}, 0);
const burrowOn = () => burrow.on;
// Burrow's addons: the same format as Selkies Forge's (burrow/addons.mjs).
const addons = new Addons({
  dir: join(DATA, "addons"), registry: join(DATA, "addons.json"), version: VERSION, log, tunnels,
  onChange: () => { syncExtensions(); },
  // what an automatic path skipped because it needs root goes on the bell
  notify: (n) => { try { notify("aegis", n); } catch (e) { log("addons:", e.message); } },
  env: () => {
    const e = { ADDON_HOST_URL: `${TLS ? "https" : "http"}://${ORIGIN_HOST}:${LISTEN.port}/`, ADDON_BIND: LISTEN.host,
                // the short path when data/ is deep: curl and others refuse socket paths over ~107 bytes
                BURROW_SOCKET: burrow.controlReal || join(DATA, "control.sock"), BURROW_NODE: process.execPath };
    // the Selkies Forge on this machine, when one registered: addons that talk to it find it
    const f = listIntegrations().find((i) => i.kind === "selkies-forge");
    if (f) Object.assign(e, { FORGE_URL: f.url || "", FORGE_API: f.api || "", ...(f.home ? { FORGE_HOME: f.home } : {}) });
    return e;
  },
});
// Burrow Pages (GitHub & GitLab Pages behind a password) is an addon of its own;
// while it is installed, Burrow offers sites.
const PAGES = "burrow-pages";
const pagesRec = () => addons.load()[PAGES] || null;
burrow.sitesAllowed = () => !!pagesRec()?.installed;
function pagesView() {
  const rec = pagesRec();
  let sites = 0;
  for (const t of tunnels.tunnels.values()) if (t.kind === "site") sites++;
  return { installed: !!rec?.installed, added: !!rec, sites, version: rec?.manifest?.version || null,
           logo: rec ? `/__gate/api/addons/${PAGES}/image?v=${(rec.commit || "").slice(0, 12)}` : "/__gate/logos/burrow-pages.svg" };
}

// ---------- addons that extend Burrow (manifest "burrow": {extension, ui}) ----------
// An installed addon may bring code that runs inside Burrow, and a panel for
// the Burrow page. Its scripts already run as this user with this data, so
// this gives it nothing new; it gets a context, not the whole server:
//
//   start(ctx)  stop()  handle({method, path, query, json(), unseal(), via})
//     -> {status, json} | {status, body, type}
//
// and, for a shield (Bulwark), hooks on every request (synchronous, cheap):
//   guard(ip, info) -> null | {status, body}   before anything else; takes the
//                                               built-in shield's place while loaded
//   observe(ip, info, {status, bytes, ms})      when the response is done
//   signedIn(ip)  peek(ip)  lookup(ip)          sign-ins; badges; IP checks
//   mount() -> {prefix, upstream, headers, name}   its app under the dashboard's login
//   ctx.fleet: your other machines, and forward(machine, port) -> a port here that reaches
//             that machine's own 127.0.0.1:port (an SSH forward, kept up until released)
//   programs: [{id, name, note, install(machine, tools)}]   things Fleet can install on
//             a linked machine (Machines -> Install); tools.run(script) runs there over
//             Fleet's own link, tools.log/step feed the job. Returns {url?, version?}.
//
// Routes: /__gate/api/x/<id>/… (signed in) and /x/<id>/… on the control
// socket; the panel is /__gate/x/<id>/ui.js. Burrow Pages is the first.
const extensions = new Map();          // id -> { mod, commit, ctx, ui }
function extContext(rec) {
  const id = rec.id, own = (port) => { const t = tunnels.get(port); if (!t || t.app !== id) throw new Error("That tunnel isn't this addon's."); return t; };
  return {
    id, hostVersion: VERSION, dataDir: addons.dataDir(rec), root: addons.rootOf(rec),
    legacyShield: join(DATA, "shield"),
    kick: (ip) => { let n = 0; for (const t of tunnels.list()) n += tunnels.kick(t.port, ip); return n; },
    log: (...a) => log(`${id}:`, ...a),
    // a warning for the dashboard (the bell; a banner if critical)
    notify: (n) => notify(id, n),
    // what the gate remembers: each tunnel's clients and recent requests, and the audit log
    history: ({ since = 0 } = {}) => ({
      tunnels: tunnels.list().map((t) => {
        const rt = tunnels.live.get(t.port);
        return { port: t.port, host: t.host || t.url?.replace(/^https?:\/\//, "") || null, name: t.name || null,
                 clients: rt ? [...rt.clients.values()].filter((c) => c.last >= since).map(({ sockets, active, ...c }) => c) : [],
                 recent: rt ? rt.recent.filter((r) => r.t >= since) : [] };
      }),
      audit: auditRead(2000).filter((e) => Date.parse(e.t) >= since),
    }),
    setting: (key) => { const r = addons.load()[id]; return r?.settings?.[key] ?? r?.manifest.settings.find((s) => s.key === key)?.default ?? ""; },
    domain: () => { const d = settings.get("domain"); return d ? { mainHost: d.mainHost, zone: d.mainHost.split(".").slice(1).join("."), managed: !!d.managed } : null; },
    dns: () => tunnels.dnsRecords(),
    // your devices (aegis/devices.mjs): each with its addresses, and the addresses they used lately
    devices: () => ({ list: devices.list(null), addresses: devices.addresses() }),
    tunnels: {
      list: () => tunnels.list(),
      create: (spec) => tunnels.create({ ...spec, app: id }),
      update: (port, patch) => { own(port); return tunnels.update(port, patch); },
      remove: (port) => { own(port); return tunnels.remove(port); },
    },
    // your other machines (Machines), and a port of one answering here: forward(machine, port)
    // -> {host: "127.0.0.1", port, state}; kept up until release(machine, port) or the addon unloads
    fleet: {
      enabled: () => fleet.enabled(),
      list: () => (fleet.enabled() ? fleet.list() : []).map((m) => ({ id: m.id, name: m.name, address: m.address, os: m.os || "", arch: m.arch || "",
                                                                       up: machineUp(m), standby: !!m.standby, via: m.via || "direct" })),
      forward: (machine, port) => { const v = fleet.forward(machine, port, id); return { ...v, port: v.local }; },
      release: (machine, port) => fleet.release(machine, port, id),
      forwards: () => fleet.forwards().filter((f) => f.owners.includes(id)).map(({ owners, ...f }) => f),
    },
  };
}
// which copy of an addon is installed: a new commit, or a folder copied again, means reload
const extVersion = (rec) => `${rec.commit || ""}|${rec.updated || ""}|${rec.installed_at || ""}`;
// Node keeps every module it loaded, by its path: reloading an addon's entry
// with ?v= gets a new entry, but the files it imports stay the old ones until
// the gate restarts. So an addon loaded again in this process is loaded from a
// fresh snapshot of its folder (hard links: instant, no extra space), a new
// path for every file. Older snapshots go once the new one runs.
const loadedOnce = new Set();
function loadRoot(rec) {
  const root = join(addons.addonDir(rec.id), "repo");
  if (!loadedOnce.has(rec.id)) {
    loadedOnce.add(rec.id);
    rmSync(join(addons.addonDir(rec.id), ".loaded"), { recursive: true, force: true });       // a previous run's
    return addons.rootOf(rec);
  }
  const base = join(addons.addonDir(rec.id), ".loaded"), snap = join(base, String(Date.now()));
  mkdirSync(base, { recursive: true, mode: 0o700 });
  linkTree(root, snap);
  for (const old of readdirSync(base)) if (join(base, old) !== snap) rmSync(join(base, old), { recursive: true, force: true });
  return join(snap, rec.subdir || "");
}
// a folder, again, as hard links (a plain copy where that can't be done); links stay links
function linkTree(src, dst) {
  mkdirSync(dst, { recursive: true, mode: 0o700 });
  for (const e of readdirSync(src, { withFileTypes: true })) {
    const a = join(src, e.name), b = join(dst, e.name);
    if (e.isDirectory()) linkTree(a, b);
    else if (e.isSymbolicLink()) symlinkSync(readlinkSync(a), b);
    else if (e.isFile()) { try { linkSync(a, b); } catch { copyFileSync(a, b); } }
  }
}
async function syncExtensions() {
  const all = addons.load();
  for (const [id, x] of extensions) {
    const rec = all[id];
    if (!rec?.installed || extVersion(rec) !== x.version) {
      extensions.delete(id);
      try { fleet.releaseAll(id); } catch { /* none */ }
      try { await x.mod.stop?.(); } catch (e) { log(`${id}: stop failed`, e.message); }
      log(`${id}: unloaded`);
    }
  }
  for (const rec of Object.values(all)) {
    const b = rec.installed && rec.manifest.burrow;
    if (!b || extensions.has(rec.id)) continue;
    const x = { mod: {}, commit: rec.commit, version: extVersion(rec), ui: b.ui ? join(addons.rootOf(rec), b.ui) : null, ctx: null };
    extensions.set(rec.id, x);
    if (!b.extension) continue;
    try {
      x.mod = await import(`${pathToFileURL(join(loadRoot(rec), b.extension)).href}?v=${Date.now()}`);
      x.ctx = extContext(rec);
      await x.mod.start?.(x.ctx);
      log(`${rec.id}: running inside Burrow${x.mod.guard ? " (guarding every request)" : ""}`);
    } catch (e) { x.error = e.message; log(`${rec.id}: its extension failed to start:`, e.message); }
  }
  useGuard();
}
// the shield in use: a guard addon's (Bulwark) while one is loaded, else the built-in one
let guardExt = null;
function useGuard() {
  const g = [...extensions.values()].find((x) => typeof x.mod.guard === "function" && !x.error)?.mod || null;
  if (g === guardExt) return;
  guardExt = g; burrow.guardExt = g;
  if (g) { burrow.shield.stop(); log("shield: an addon guards every request now; the built-in shield rests"); }
  else if (process.env.AEGIS_SHIELD_OFFLINE !== "1") { burrow.shield.start(); log("shield: the built-in shield guards every request"); }
}
async function extRoute(id, path, method, query, json, via) {
  const x = extensions.get(id);
  if (!x || !x.mod.handle) return { status: 404, json: { error: x?.error ? `That addon's extension failed to start: ${x.error}` : "That addon isn't installed." } };
  try { return (await x.mod.handle({ method, path, query, json, unseal: unwrapSealed, via })) || { status: 404, json: { error: "not found" } }; }
  catch (e) { return { status: e.status || 400, json: { error: e.message } }; }
}
setTimeout(syncExtensions, 1500);
setInterval(syncExtensions, 60000);

// Addons that come with Aegis × Burrow: each is installed once, a little after
// the first start (or the update that brought it). One you uninstall stays
// uninstalled: state.json's defaultAddons remembers it was done. Bulwark is
// asked about first (ask: the welcome page recommends it, ticked): a new
// install gets it only once the pack is decided and it wasn't turned down;
// an install from before that question existed (no answer on record) gets it.
const DEFAULT_ADDONS = [{ id: PAGES, source: "https://github.com/alexd-aero/burrow-pages" },
                        { id: "bulwark", source: "https://github.com/alexd-aero/bulwark", ask: true }];
const markDefault = (id) => settings.set({ defaultAddons: { ...(settings.get("defaultAddons") || {}), [id]: Date.now() } });
async function installDefault(id, say = () => {}) {
  const d = DEFAULT_ADDONS.find((x) => x.id === id);
  if (!addons.load()[id]) { say("fetching it…"); await addons.add(d.source); }
  if (!addons.load()[id].installed) {
    const { id: job } = addons.install(id, {});
    let seen = 0;
    for (;;) {
      await new Promise((r) => setTimeout(r, 1000));
      const j = addons.job(job);
      for (const l of (j.lines || []).slice(seen)) if (l.line?.trim()) say(String(l.line).slice(0, 200));
      seen = (j.lines || []).length;
      if (j.state === "running") continue;
      if (j.state !== "done") throw new Error(j.error || j.state);
      break;
    }
  }
  markDefault(id);
  log("addons:", id, "is installed (it comes with Aegis × Burrow)");
}
async function defaultAddons() {
  if (process.env.AEGIS_NO_DEFAULT_ADDONS) return;
  for (const d of DEFAULT_ADDONS) {
    if ((settings.get("defaultAddons") || {})[d.id]) continue;
    if (d.ask) {
      const p = settings.get("pack") || {};
      if (!p.decided) continue;                                   // the welcome page asks first
      if (p.bulwark === false) { markDefault(d.id); log("addons:", d.id, "was turned down on the welcome page"); continue; }
    }
    try { await installDefault(d.id); }
    catch (e) { log("addons: couldn't install", d.id, "by default:", e.message, "- trying again later"); }
  }
}
setTimeout(defaultAddons, 30000);
// addons from a link get checked for updates like Aegis × Burrow itself: their
// cards on the home and Burrow pages then offer the update, no visit needed
setTimeout(() => addons.checkAll(), 120000).unref();
// the watchdog: addons (Selkies Forge among them) that stop on their own
setTimeout(addons.watch(60e3), 45000).unref();
setInterval(() => addons.checkAll(50 * 60e3), 3600e3).unref();      // every hour (a git ls-remote each)
setInterval(defaultAddons, 6 * 3600 * 1000);

// Both ways: once the Forge has us as an addon, we add it as one of ours.
const bridgeTick = () => adoptForge({ addons, log }).catch((e) => log("bridge:", e.message));
setTimeout(bridgeTick, 20000);
setInterval(bridgeTick, 120000);
const termix = new Termix({ settings, log });
// Machine management: other machines you own, reached over SSH (aegis/fleet.mjs).
// Off until Settings -> Modules switches it on; every route below says so.
const fleet = new Fleet({
  settings, dir: join(DATA, "fleet"), file: join(DATA, "fleet.json"), log, version: VERSION, notify,
  dashboards: () => [...dashboards(null).map((d) => d.host), ...(serveo.host() ? [serveo.host()] : []),
                     ...(settings.get("extraHosts") || []), ...localAddrs, "localhost", "127.0.0.1"],
});
// linked machines' agents: the way in when SSH can't reach them directly (aegis/fleet-agent.mjs)
const fleetAgents = new AgentHub({ fleet, log,
  sock: join(process.env.XDG_RUNTIME_DIR || tmpdir(), `aegis-fleet-${process.getuid?.() ?? 0}-${createHash("sha256").update(HOME).digest("hex").slice(0, 10)}.sock`) });
fleet.agents = fleetAgents;
fleetAgents.listen();
fleet.startBeat();
const pack = new Pack({ settings, termix, log, tunnels, addon: { has: (id) => !!addons.load()[id]?.installed, install: (id, say) => installDefault(id, say) } });
// Updates from GitHub, by hand or by itself (Settings → Updates)
const updater = new Updater({ settings, log, exit: () => { burrow.stop(); serveo.stop(); process.exit(0); } });
// aegis/server.mjs put the version before back by itself: say so, once
updater.onRolledBack = (b) => notify("aegis", { level: "critical", key: "rolled-back", title: `Aegis × Burrow ${b.failed} didn't start, so ${b.to} is back`,
  body: `v${b.failed} ${b.why || "failed"}. Aegis went back to v${b.to} by itself; everything you set up is as it was. v${b.failed} is held back from auto-update (Settings → Updates → Versions to allow it again).`,
  link: "/__gate/settings#updates" });

// the serveo link sends visitors on to the domain, once there is one (Settings → Modules)
const serveoForward = () => settings.get("serveoForward") !== false;
const mainHost = () => settings.get("domain")?.mainHost?.toLowerCase() || null;
// the dashboard answers here: the main domain's name, local names, the serveo link, and another domain's dashboard name
const isDashHost = (host) => host === mainHost() || isLocalName(host) || host === serveo.host() || burrow.domains.isDashboard(host);
// Your dashboards on the web: the main one and one per other domain that has a
// dashboard name. Signed in on any of them, the switcher in the top bar opens
// the others signed in too (a ticket hop, like a login tunnel's).
function dashboards(current) {
  const out = [], main = mainHost();
  if (main) out.push({ host: main, zone: main.split(".").slice(1).join("."), main: true });
  for (const d of burrow.domains.list()) if (d.label) out.push({ host: burrow.domains.dashboardOf(d), zone: d.zone.name, main: false });
  const seen = new Set();
  return out.filter((x) => !seen.has(x.host) && seen.add(x.host)).map((x) => ({ ...x, current: x.host === current }));
}
const isWebDash = (host) => !!host && (host === mainHost() || burrow.domains.isDashboard(host));

// ---------- helpers ----------

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64u = (s) => Buffer.from(String(s ?? ""), "base64url");
const sha256 = (s) => createHash("sha256").update(s).digest();
const hostOf = (req) => String(req.headers.host || "").toLowerCase().replace(/:\d+$/, "");
const isLoopback = (a) => /^(127\.|::1$|::ffff:127\.)/.test(String(a || ""));
// This machine: loopback, or any of its own addresses. When we listen on a
// LAN or Tailscale address, cloudflared's connection arrives from whichever
// local address the kernel picks (often the LAN one), not from 127.0.0.1.
let localAddrs = new Set();
function refreshLocalAddrs() {
  const out = new Set();
  for (const list of Object.values(networkInterfaces())) for (const i of list || []) out.add(i.address);
  localAddrs = out;
}
refreshLocalAddrs();
setInterval(refreshLocalAddrs, 60000).unref();
const isThisMachine = (a) => isLoopback(a) || localAddrs.has(String(a || "").replace(/^::ffff:/, ""));
// cloudflared runs on this machine, so only this machine may tell us who the client is
const viaProxy = (req) => isThisMachine(req.socket.remoteAddress) && !!req.headers["cf-connecting-ip"];
// serveo connects from this machine (our ssh) and names the visitor in X-Real-Ip
const viaServeo = (req) => isThisMachine(req.socket.remoteAddress) && !!serveo.host() && hostOf(req) === serveo.host();
const clientIp = (req) => (viaProxy(req) ? req.headers["cf-connecting-ip"]
  : viaServeo(req) ? (req.headers["x-real-ip"] || String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "serveo")
  : req.socket.remoteAddress) || "?";
const isSecure = (req) => !!req.socket.encrypted || (isThisMachine(req.socket.remoteAddress) && req.headers["x-forwarded-proto"] === "https");
const cookieName = (req) => (isSecure(req) ? COOKIE : PLAIN_COOKIE);
const goName = (req) => (isSecure(req) ? "__Host-" + GO : GO);
const cookieAttrs = (req, maxAge) => `Path=/; ${isSecure(req) ? "Secure; " : ""}HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;

function isLocalName(host) {
  if (!host) return false;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) return true;
  if (!host.includes(".")) return true;
  if (/\.(local|lan|home\.arpa|internal|ts\.net)$/.test(host)) return true;
  return (settings.get("extraHosts") || []).map((x) => String(x).toLowerCase()).includes(host);
}

function parseCookies(header) {
  const out = {};
  for (const part of (header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function stripGateCookie(header) {
  if (!header) return header;
  const ours = [COOKIE, PLAIN_COOKIE, GO, "__Host-" + GO, UNLOCK, "__Host-" + UNLOCK, DEVICE, "__Host-" + DEVICE].map((n) => n + "=");
  const kept = header.split(";").map((p) => p.trim()).filter((p) => p && !ours.some((n) => p.startsWith(n)));
  return kept.length ? kept.join("; ") : undefined;
}

// A redirect target inside this host only.
function safeNext(n, fallback) {
  const s = String(n || "");
  return /^\/(?!\/)[^\s\\]*$/.test(s) && !s.startsWith("/__gate/api") ? s : fallback;
}

// ---------- session token (AES-256-GCM sealed, bound to a host) ----------

function seal(obj, aad) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", SESSION_KEY, iv);
  c.setAAD(Buffer.from(aad));
  const body = Buffer.concat([c.update(JSON.stringify(obj)), c.final()]);
  return b64u(Buffer.concat([iv, body, c.getAuthTag()]));
}

function unseal(token, aad) {
  try {
    const raw = unb64u(token);
    if (raw.length < 12 + 16 + 2) return null;
    const d = createDecipheriv("aes-256-gcm", SESSION_KEY, raw.subarray(0, 12));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(raw.subarray(raw.length - 16));
    return JSON.parse(Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString());
  } catch { return null; }
}

// sid ties every cookie back to the dashboard sign-in it came from; e is the
// password's epoch, so changing the password signs every browser out.
const sealSession = (username, host, sid) =>
  seal({ u: username, h: host, sid, e: settings.auth()?.epoch, exp: Date.now() + sessionTtl(), n: b64u(randomBytes(8)) }, COOKIE);

const revoked = new Map(); // sid -> expiry
try { for (const [sid, exp] of Object.entries(JSON.parse(readFileSync(REVOKED_FILE, "utf8")))) revoked.set(sid, exp); } catch { /* none */ }
function revoke(sid) {
  if (!sid) return;
  const now = Date.now();
  for (const [k, exp] of revoked) if (exp < now) revoked.delete(k);
  revoked.set(sid, now + sessionTtl());
  try { writeFileSync(REVOKED_FILE + ".tmp", JSON.stringify(Object.fromEntries(revoked))); renameSync(REVOKED_FILE + ".tmp", REVOKED_FILE); }
  catch (e) { log("revoke: could not save", e.message); }
}

function openSession(token, host) {
  const s = unseal(token, COOKIE);
  const auth = settings.auth();
  if (!s || !auth || s.exp <= Date.now()) return null;
  if (s.h && s.h !== host) return null;
  if (s.sid && revoked.has(s.sid)) return null;
  if ((s.e || null) !== (auth.epoch || null)) return null;
  return s;
}

const sessionOf = (req) => openSession(parseCookies(req.headers.cookie)[cookieName(req)], hostOf(req));
const isAuthed = (req) => !!sessionOf(req);
const sessionCookie = (req, sid) =>
  `${cookieName(req)}=${sealSession(settings.auth().username, hostOf(req), sid)}; ${cookieAttrs(req, sessionTtl() / 1000)}`;
const clearSessionCookie = (req) => `${cookieName(req)}=; ${cookieAttrs(req, 0)}`;

// ---------- your devices: the device key (aegis/devices.mjs) ----------
const deviceName_ = (req) => (isSecure(req) ? "__Host-" + DEVICE : DEVICE);
const deviceCookie = (req, id) => `${deviceName_(req)}=${seal({ d: id, e: settings.auth()?.epoch || null }, DEVICE)}; ${cookieAttrs(req, DEVICE_TTL_S)}`;
function deviceOf(req) {
  if (req._dev !== undefined) return req._dev;
  const raw = parseCookies(req.headers.cookie)[deviceName_(req)];
  const s = raw ? unseal(raw, DEVICE) : null;
  return (req._dev = s && (s.e || null) === (settings.auth()?.epoch || null) && devices.has(s.d) ? s.d : null);
}
// a sign-in: this browser's device key (the one it had, or a new one)
const enrollDevice = (req) => deviceCookie(req, devices.enroll(deviceOf(req), { ip: clientIp(req), ua: req.headers["user-agent"], host: hostOf(req) }));

function renewalCookie(req) {
  const s = sessionOf(req);
  if (!s || s.exp - Date.now() > sessionTtl() - SESSION_RENEW_MS) return null;
  return sessionCookie(req, s.sid || b64u(randomBytes(12)));
}

// ---------- a tunnel's own password ----------
// A tunnel with access "password" opens with its own password (Burrow keeps
// the scrypt hash, t.lock) or with the Aegis login. The cookie is bound to the
// tunnel, its host and the password's epoch: a new password locks everyone out.

const unlockName = (req) => (isSecure(req) ? "__Host-" + UNLOCK : UNLOCK);
const unlockCookie = (req, t) => `${unlockName(req)}=${seal({ p: t.port, h: hostOf(req), e: t.lock.epoch, exp: Date.now() + sessionTtl() }, UNLOCK)}; ${cookieAttrs(req, sessionTtl() / 1000)}`;
function unlocked(req, t) {
  const s = t.lock && unseal(parseCookies(req.headers.cookie)[unlockName(req)] || "", UNLOCK);
  return !!(s && s.p === t.port && s.h === hostOf(req) && s.e === t.lock.epoch && s.exp > Date.now());
}
// Another Aegis × Burrow that had the password clones the tunnel (burrow/clone.mjs):
// its key rides on every request it passes on, and dies with this password.
function cloneKeyOk(req, t) {
  const k = req.headers["x-burrow-clone"];
  const s = t.lock && typeof k === "string" && k.length < 600 && unseal(k, CLONE);
  return !!(s && s.p === t.port && s.h === hostOf(req) && s.e === t.lock.epoch);
}
// anyone (public), the Aegis login (login, and password too), or its own password (or a clone's key for it)
const mayOpen = (req, t) => t.access === "public" || isAuthed(req) || (t.access === "password" && (unlocked(req, t) || cloneKeyOk(req, t)));

function unlockPage(res, t, host) {
  const html = FILES["unlock.html"].toString().replaceAll("{{name}}", esc(t.name || t.site?.host || `tunnel-${t.port}`))
    .replaceAll("{{host}}", esc(host)).replaceAll("{{title}}", esc(settings.get("title")));
  send(res, 200, html, { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": GATE_CSP });
}

async function unlockRoute(t, req, res, url, host) {
  if (req.method === "GET") {
    if (mayOpen(req, t)) return send(res, 302, "", { Location: safeNext(url.searchParams.get("next"), "/") });
    return unlockPage(res, t, host);
  }
  if (req.method !== "POST") return send(res, 405, "");
  const ip = clientIp(req);
  if (tooManyFails(ip)) { log("unlock throttled", ip, host); return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." }); }
  let f;
  try { f = await unwrapSealed(await readJsonBody(req)); }
  catch { recordFail(ip); return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." }); }
  if (!checkLock(t.lock, f.password)) { recordFail(ip); log("unlock wrong password", ip, host); audit("tunnel password wrong", req); return sendJson(res, 401, { error: "Wrong password." }); }
  fails.delete(ip); log("unlock ok", ip, host); audit("tunnel unlocked", req);
  return sendJson(res, 200, { ok: true, next: safeNext(f.next, "/") }, { "Set-Cookie": unlockCookie(req, t) });
}

// Who may open this link, for another gate that wants to clone it. A link behind
// the Aegis login answers too ("login", and nothing more), so the other side can say why not.
function burrowInfo(t, res, host) {
  if (!t.enabled) return sendJson(res, 404, { burrow: 1, error: "paused" });
  if (t.access === "login") return sendJson(res, 200, { burrow: 1, aegis: VERSION, access: "login" });
  sendJson(res, 200, { burrow: 1, aegis: VERSION, access: t.access, name: t.name || tunnels.runtime(t.port).title || host });
}

// A clone key for the tunnel's password: the same throttle and sealing as the unlock page.
async function cloneRoute(t, req, res, host) {
  if (req.method !== "POST") return send(res, 405, "");
  const ip = clientIp(req);
  if (tooManyFails(ip)) { log("clone throttled", ip, host); return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." }); }
  let f;
  try { f = await unwrapSealed(await readJsonBody(req)); }
  catch { recordFail(ip); return sendJson(res, 400, { error: "Secure handshake failed." }); }
  if (!checkLock(t.lock, f.password)) { recordFail(ip); log("clone wrong password", ip, host); audit("tunnel password wrong (clone)", req); return sendJson(res, 401, { error: "Wrong password." }); }
  fails.delete(ip); log("cloned", host, "by", ip); audit("tunnel cloned", req, { tunnel: t.port });
  try {
    notify("aegis", { level: "info", key: `cloned-${t.port}`, title: `${t.name || host} was cloned`,
      body: `Someone with its password cloned it onto their own Aegis × Burrow. A clone opens it the way the password does. Change its password to cut every clone off.`,
      link: "/__gate/tunnels", items: [{ label: ip, sub: host }] });
  } catch { /* the bell is a courtesy */ }
  return sendJson(res, 200, { key: seal({ p: t.port, h: host, e: t.lock.epoch, at: Date.now() }, CLONE) });
}

// ---------- single sign-on tickets (dashboard -> tunnel host) ----------

const usedTickets = new Map(); // n -> expiry
const sealTicket = (host, sid, dev = null) => seal({ h: host, sid, dev, exp: Date.now() + TICKET_TTL_MS, n: b64u(randomBytes(12)) }, "tgate-sso");
function openTicket(token, host) {
  const t = unseal(token, "tgate-sso");
  const now = Date.now();
  for (const [k, exp] of usedTickets) if (exp < now) usedTickets.delete(k);
  if (!t || t.exp <= now || t.h !== host || usedTickets.has(t.n)) return null;
  if (t.sid && revoked.has(t.sid)) return null;
  usedTickets.set(t.n, t.exp);
  return t;
}
const ssoUrl = (host, next) =>
  `https://${mainHost()}/__gate/sso?to=${encodeURIComponent(host)}&next=${encodeURIComponent(safeNext(next, "/"))}`;

// ---------- credentials ----------

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
function hashPassword(password, salt) { return scryptSync(String(password), salt, 32, SCRYPT); }

function checkCredentials(username, password) {
  const auth = settings.auth();
  if (!auth) return false;
  const userOk = timingSafeEqual(sha256(String(username)), sha256(auth.username));
  const passOk = timingSafeEqual(hashPassword(password, unb64u(auth.salt)), unb64u(auth.hash));
  return userOk && passOk;
}

function setPassword(username, password) {
  const salt = randomBytes(16);
  settings.set({ auth: { username, salt: b64u(salt), hash: b64u(hashPassword(password, salt)), epoch: b64u(randomBytes(6)), changed: Date.now() },
                 setupToken: null });
}

// ---------- brute-force limiter ----------

const fails = new Map(); // ip -> [timestamps]
function tooManyFails(ip) {
  const now = Date.now();
  const list = (fails.get(ip) || []).filter((t) => now - t < lockout().windowMs);
  fails.set(ip, list);
  return list.length >= lockout().fails;
}
const recordFail = (ip) => fails.set(ip, [...(fails.get(ip) || []), Date.now()]);

// ---------- PQ challenge / double AES-256-GCM unwrap ----------

const challenges = new Map(); // id -> { secretKey, exp }

function newChallenge() {
  const now = Date.now();
  for (const [id, c] of challenges) if (c.exp < now) challenges.delete(id);
  if (challenges.size > 1000) challenges.clear();
  const { publicKey, secretKey } = xwing.keygen();
  const id = randomUUID();
  challenges.set(id, { secretKey, exp: now + CHALLENGE_TTL_MS });
  return { id, pk: b64u(publicKey), kem: "X-Wing (ML-KEM-768 + X25519)", aead: "AES-256-GCM x2" };
}

async function deriveKey(ss, salt, label) {
  const base = await webcrypto.subtle.importKey("raw", ss, "HKDF", false, ["deriveKey"]);
  return webcrypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-384", salt: new TextEncoder().encode(salt), info: new TextEncoder().encode(label) },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}

async function unwrapSealed(msg) {
  const ch = challenges.get(msg.id);
  challenges.delete(msg.id); // single use
  if (!ch || ch.exp < Date.now()) throw new Error("challenge expired");
  const ss = xwing.decapsulate(unb64u(msg.ct), ch.secretKey);
  const kOuter = await deriveKey(ss, msg.id, "aegis/v1/outer");
  const kInner = await deriveKey(ss, msg.id, "aegis/v1/inner");
  const inner = Buffer.from(await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64u(msg.iv), additionalData: new TextEncoder().encode("outer|" + msg.id) },
    kOuter, unb64u(msg.c)));
  const plain = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: inner.subarray(0, 12), additionalData: new TextEncoder().encode("inner|" + msg.id) },
    kInner, inner.subarray(12));
  return JSON.parse(new TextDecoder().decode(plain));
}

function readBody(req, limit = 16384) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > limit) { reject(new Error("too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}
const readJsonBody = async (req) => JSON.parse((await readBody(req)) || "{}");

const SEC_HEADERS = { "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" };
const GATE_CSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
  + "connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

function send(res, status, body, headers = {}) {
  const sec = res.req && isSecure(res.req) ? { "Strict-Transport-Security": "max-age=31536000" } : {};
  // text without a type, under nosniff, is a page Chrome won't show (ERR_INVALID_RESPONSE)
  const type = body && !Object.keys(headers).some((k) => k.toLowerCase() === "content-type") ? { "Content-Type": "text/plain; charset=utf-8" } : {};
  res.writeHead(status, { ...SEC_HEADERS, ...sec, ...type, ...headers });
  res.end(body);
}
const sendJson = (res, status, obj, headers = {}) =>
  send(res, status, JSON.stringify(obj), { "Content-Type": "application/json", ...headers });
// Pages are templated per request, so a new title or sign-in text shows at once.
const page = (res, name, headers = {}) => {
  const l = settings.get("login") || {};
  const html = FILES[name].toString().replaceAll("{{title}}", esc(settings.get("title")))
    .replaceAll("{{subtitle}}", esc(l.subtitle || "Secure channel"));
  send(res, 200, html, { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": GATE_CSP, ...headers });
};

function messagePage(res, status, title, text) {
  send(res, status, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#030304;color:#e8eaed;font:14px/1.5 system-ui,sans-serif}
.c{max-width:380px;padding:26px 28px;border:1px solid rgba(255,255,255,.1);border-radius:16px;background:#0f1012}h1{font-size:17px;margin:0 0 6px}p{margin:0;color:#8a8f97}a{color:#e8eaed}</style></head>
<body><div class="c"><h1>${title}</h1><p>${text}</p></div></body></html>`, { "Content-Type": "text/html; charset=utf-8" });
}

// First run: no login yet. Someone sitting at this machine may create it;
// anyone else needs the one-time setup link the installer printed.
function setupAllowed(req, token) {
  const want = settings.setupToken();
  if (want && token && timingSafeEqual(sha256(String(token)), sha256(want))) return true;
  if (isLoopback(req.socket.remoteAddress) && !req.headers["cf-connecting-ip"] && !req.headers["x-forwarded-for"]
      && !req.headers["x-real-ip"] && !viaServeo(req)) return true;
  // No link token needed: the first login can be created from anywhere for
  // 30 minutes after Aegis starts (aegis restart opens the window again).
  return Date.now() - startedAt < SETUP_WINDOW_MS;
}

// ---------- gate routes (any host) ----------

async function handleGate(req, res, path, url, host, isMain) {
  const hasDomain = !!mainHost();
  if (path === "/__gate/health") return sendJson(res, 200, { ok: true, app: "aegis-burrow", version: VERSION, burrow: burrow.on, standby: process.env.AEGIS_STANDBY === "1" });
  const asset = path.slice("/__gate/".length);
  if (FILES[asset] && !asset.endsWith(".html")) {
    return send(res, 200, FILES[asset], { "Content-Type": TYPES[extname(asset)], "Cache-Control": "no-cache" });
  }
  if (path === "/__gate/challenge" && req.method === "POST") return sendJson(res, 200, newChallenge());

  if (!settings.auth()) {
    if (!isMain) return messagePage(res, 503, "Not set up yet", "Aegis needs its first login before tunnels work.");
    if (path === "/__gate/setup" && req.method === "GET") return page(res, "setup.html");
    if (path === "/__gate/setup" && req.method === "POST") {
      let f;
      try { f = await unwrapSealed(await readJsonBody(req)); }
      catch { return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." }); }
      if (!setupAllowed(req, f.token)) return sendJson(res, 403, { error: "This setup link is not valid. Use the one the installer printed (`aegis setup-link`)." });
      const username = String(f.username || "").trim();
      if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) return sendJson(res, 400, { error: "Username: 2-64 letters, digits, . _ @ -" });
      if (String(f.password || "").length < 10) return sendJson(res, 400, { error: "Use at least 10 characters." });
      setPassword(username, f.password);
      log("setup: login created for", username, "from", clientIp(req));
      return sendJson(res, 200, { ok: true, next: "/__gate/welcome" }, { "Set-Cookie": sessionCookie(req, b64u(randomBytes(12))) });
    }
    return send(res, 302, "", { Location: "/__gate/setup" + url.search });
  }
  if (path === "/__gate/setup") return send(res, 302, "", { Location: "/" });

  // ---- Aegis Relay: the one-time install script for your VPS, and its "done" (both need the setup link's token)
  if (path === "/__gate/relay/agent.sh" && req.method === "GET" && isMain) {
    const sc = relayLink.script(url.searchParams.get("t"), { base: `https://${mainHost() || host}` });
    if (!sc) return send(res, 404, "echo 'That setup link has expired or is wrong: make a new one in Aegis → Settings → Domain.' >&2; exit 1\n", { "Content-Type": "text/plain; charset=utf-8" });
    audit("relay setup script fetched", req, { relay: relayLink.state.token?.host });
    return send(res, 200, sc, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  }
  if (path === "/__gate/relay/register" && req.method === "POST" && isMain) {
    try {
      const r = relayLink.register(url.searchParams.get("t"), await readJsonBody(req));
      audit("relay registered", req, { relay: relayLink.state.vps?.host });
      // the installer waits for this: can this machine really reach the agent over the locked-down SSH user?
      const v = await verifyRelay();
      if (v.ok) setTimeout(() => relayMachine({ bringUp: true }).catch(() => {}), 3000);      // and into Machines, the same go
      return sendJson(res, 200, { ...r, linked: v.ok, error: v.error });
    }
    catch (e) { return sendJson(res, 400, { error: e.message }); }
  }

  if (path === "/__gate/login" && req.method === "GET") {
    if (isAuthed(req)) return send(res, 302, "", { Location: safeNext(url.searchParams.get("next"), "/") });
    // With a domain, tunnel hosts sign in through the dashboard, so one login covers them all.
    if (!isMain && hasDomain) return send(res, 302, "", { Location: ssoUrl(host, url.searchParams.get("next")) });
    return page(res, "login.html");
  }
  if (path === "/__gate/auth" && req.method === "POST") {
    const ip = clientIp(req);
    if (tooManyFails(ip)) {
      log("auth throttled", ip, host); audit("sign-in throttled", req);
      return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
    }
    let creds;
    try { creds = await unwrapSealed(await readJsonBody(req)); }
    catch (e) {
      recordFail(ip); log("auth decrypt failed", ip, e.message); audit("sign-in garbled", req);
      return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." });
    }
    if (!checkCredentials(creds.username, creds.password)) {
      recordFail(ip); log("auth bad credentials", ip, host);
      audit("sign-in failed", req, { user: String(creds.username || "").slice(0, 64), why: creds.username === settings.auth()?.username ? "wrong password" : "unknown username" });
      return sendJson(res, 401, { error: "Invalid username or password." });
    }
    fails.delete(ip); log("auth ok", ip, host); audit("sign-in", req, { user: String(creds.username || "") });
    burrow.shield.trust(ip);
    try { guardExt?.signedIn?.(ip); } catch { /* the addon's business */ }
    return sendJson(res, 200, { ok: true, next: safeNext(creds.next, "/") }, { "Set-Cookie": [sessionCookie(req, b64u(randomBytes(12))), enrollDevice(req)] });
  }
  if (path === "/__gate/logout") {
    const s = sessionOf(req);
    if (isMain && s) { revoke(s.sid); log("logout", clientIp(req), "sid revoked"); audit("sign-out", req); }
    const to = isMain ? "/__gate/login" : hasDomain ? `https://${mainHost()}/__gate/logout` : "/";
    return send(res, 302, "", { Location: to, "Set-Cookie": clearSessionCookie(req) });
  }
  if (path === "/__gate/sso/callback" && req.method === "GET") {
    const t = openTicket(url.searchParams.get("t"), host);
    if (!t) {
      log("sso ticket refused", clientIp(req), host); audit("sign-in link refused", req);
      return messagePage(res, 403, "Sign-in expired", 'That sign-in link expired. <a href="/">Try again</a>.');
    }
    // the same device key on this host too, so the gate knows the device here even once the session ends
    const dev = t.dev && devices.has(t.dev) ? t.dev : null;
    if (dev) devices.seen(dev, { ip: clientIp(req), ua: req.headers["user-agent"], host }, true);
    return send(res, 302, "", { Location: safeNext(url.searchParams.get("next"), "/"), "Set-Cookie": [sessionCookie(req, t.sid), ...(dev ? [deviceCookie(req, dev)] : [])] });
  }
  if (!isMain) return send(res, 404, "Not found");

  // ---- dashboard: hand a login tunnel a ticket (asks for the login first if needed) ----
  if (path === "/__gate/sso" && req.method === "GET") {
    const to = String(url.searchParams.get("to") || "").toLowerCase().split(":")[0];
    // a login tunnel, or another of your dashboards (the dashboards menu: other domains' dashboards)
    const toDash = to !== host && isWebDash(to);
    const port = !toDash && burrowOn() ? tunnels.matchHost(to) : null;
    if (!toDash && (port === null || !tunnels.get(port))) {
      log("sso: nowhere to send", clientIp(req), JSON.stringify(to).slice(0, 120));
      return messagePage(res, 404, "Not one of yours", `${esc(to || "That address")} isn't a dashboard or a tunnel of this Aegis (any more). <a href="/">Back home</a>.`);
    }
    const s = sessionOf(req);
    if (!s) return send(res, 302, "", { Location: "/__gate/login?next=" + encodeURIComponent(req.url) });
    const next = safeNext(url.searchParams.get("next"), "/");
    return send(res, 302, "", { Location: `https://${to}/__gate/sso/callback?t=${sealTicket(to, s.sid, deviceOf(req))}&next=${encodeURIComponent(next)}` });
  }

  // ---- linking a machine ----
  // The other machine runs one command; it fetches the script below and
  // calls back. Both are opened with the one-shot token from "Link a
  // machine", good for half an hour, and neither reads or sets a session.
  if (path === "/__gate/fleet/join" && req.method === "GET") {
    const t = url.searchParams.get("t") || "";
    const pend = fleet.enabled() ? fleet.pending(t) : null;
    if (!pend) {
      audit("machine: link command refused", req);
      return send(res, 404, "That link command has expired. Make a new one in the dashboard.\n");
    }
    log("fleet: handing the link script to", clientIp(req));
    return send(res, 200, fleet.joinScript(t, pend.base), { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  }
  if (path === "/__gate/fleet/claim" && req.method === "POST") {
    const t = url.searchParams.get("t") || "";
    if (!fleet.enabled() || !fleet.pending(t)) {
      audit("machine: claim refused", req);
      return sendJson(res, 404, { error: "that link command has expired" });
    }
    try {
      const r = await fleet.claim(t, await readJsonBody(req), clientIp(req));
      audit("machine: linked", req, { machine: r.id, name: r.name });
      notify("fleet", { level: "info", key: "linked", title: "{n} {machine|machines} linked",
                        body: `${r.name} answered the link command and is now in Machines.`, link: "/__gate/tunnels#/machines",
                        items: [{ label: r.name, sub: clientIp(req) || "", tag: "linked" }] });
      return sendJson(res, 200, r);
    } catch (e) { return sendJson(res, 400, { error: e.message }); }
  }

  // ---- dashboard, signed in only ----
  if (!isAuthed(req)) {
    if (path.startsWith("/__gate/api/")) return sendJson(res, 401, { error: "login required" });
    return send(res, 302, "", { Location: "/__gate/login?next=" + encodeURIComponent(safeNext(req.url, "/")) });
  }
  if (path === "/__gate/choose" || path === "/__gate/home") return page(res, "home.html");
  if (path === "/__gate/open/termix") {
    if (!settings.get("termix")) return send(res, 302, "", { Location: "/__gate/settings#termix" });
    const tm = mounts().find((m) => m.id === "termix");
    const qs = termixQuery(url.searchParams);           // ?view=terminal&hostId=7: straight into that host's terminal
    if (tm) return send(res, 302, "", { Location: tm.prefix + "/" + qs });
    return send(res, 302, "", { Location: "/" + qs, "Set-Cookie": `${goName(req)}=termix; ${cookieAttrs(req, 30).replace("SameSite=Lax", "SameSite=Strict")}` });
  }
  if (path === "/__gate/tunnels") return page(res, "tunnels.html");
  const xu = /^\/__gate\/x\/([a-z0-9][a-z0-9-]{1,39})\/ui\.js$/.exec(path);
  if (xu) {
    const x = extensions.get(xu[1]);
    if (!x?.ui) return send(res, 404, "");
    return send(res, 200, readFileSync(x.ui), { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-cache" });
  }
  if (path === "/__gate/settings") return page(res, "settings.html");
  if (path === "/__gate/welcome") return page(res, "welcome.html");
  if (path.startsWith("/__gate/api/")) return handleApi(req, res, path, url);
  return send(res, 404, "Not found");
}

// ---------- dashboard API (signed in) ----------

// ---------- the serveo link (burrow/serveo.mjs) ----------
// On by default until a domain is linked (a first run has no other public
// address); after that, only if switched on in Settings → Modules.
const serveo = new Serveo({ dataDir: DATA, log });
// on unless switched off; with a domain linked it only forwards to the domain
const serveoWanted = () => settings.get("serveo") !== false;
let serveoPort = null;
function setServeo(on) {
  settings.set({ serveo: !!on });
  if (on) startServeo(); else serveo.stop();
  writeRuntime();
}
function startServeo() {
  if (serveoPort) return serveo.start(serveoPort);
  // a plain-HTTP listener on loopback just for serveo (serveo forwards HTTP,
  // and the main listener may speak TLS only, or listen on a LAN address)
  const plain = createHttpServer(handler);
  plain.on("upgrade", (...a) => server.emit("upgrade", ...a));
  plain.listen(0, "127.0.0.1", () => { serveoPort = plain.address().port; serveo.start(serveoPort); });
}

function me(req) {
  const s = sessionOf(req);
  const d = settings.get("domain");
  return {
    app: "aegis-burrow", version: VERSION, title: settings.get("title"), user: s?.u || null,
    mode: tunnels.mode, pattern: tunnels.pattern(),
    domain: d ? { mainHost: d.mainHost, managed: !!d.managed } : null,
    dashboards: dashboards(hostOf(req)),
    termix: !!settings.get("termix"),
    integrations: listIntegrations().map((i) => viewOf(i)),
    tunnels: tunnels.tunnels.size,
    modules: { burrow: burrowOn(), fleet: fleet.enabled() },
    fleet: fleetSummary(),
    home: settings.get("home") || null,
    login: { subtitle: (settings.get("login") || {}).subtitle || "Secure channel" },
    sessionDays: sessionTtl() / 864e5, lockout: { attempts: lockout().fails, minutes: lockout().windowMs / 60000 },
    pack: pack.status(),
    pages: pagesView(),
    addonUpdates: addons.updates(),
    extensions: [...extensions].filter(([, x]) => x.ui).map(([id, x]) => ({ id, ui: `/__gate/x/${id}/ui.js?v=${encodeURIComponent(x.version.replace(/\|/g, "-").slice(0, 60))}` })),
    serveo: { ...serveo.state(), forward: serveoForward() },
    mounts: { ...(settings.get("mounts") || {}) }, mountable: { termix: !!settings.get("termix"), "selkies-forge": !!listIntegrations().find((i) => i.kind === "selkies-forge" && i.url) },
    update: (({ current, latest, available, checked, title, auto, job, justUpdated }) => ({ current, latest, available, checked, title, auto, job, justUpdated }))(updater.view()),
    notices: noticesView(),
    // addons with an app of their own under the dashboard (Bulwark): a home tile each
    apps: mounts().filter((m) => extensions.has(m.id)).map((m) => ({ id: m.id, name: m.name, href: m.prefix + "/",
      logo: `/__gate/api/addons/${encodeURIComponent(m.id)}/image?v=${String(m.commit || "").slice(0, 12)}`,
      text: String(m.tile?.text || "Open its dashboard.").slice(0, 120) })),
  };
}

// ---------- preferences (Settings, and the home page's customize panel) ----------

const str = (v, n) => String(v ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, n);
function cleanHome(h) {
  if (!h || typeof h !== "object") return null;
  const id = (v) => /^[a-z0-9:_.-]{1,80}$/i.test(String(v)) ? String(v) : null;
  const links = (Array.isArray(h.links) ? h.links : []).slice(0, 24).map((l) => {
    let url = str(l.url, 500);
    try { const u = new URL(url); if (!/^https?:$/.test(u.protocol)) url = ""; } catch { url = url.startsWith("/") && !url.startsWith("//") ? url : ""; }
    return { id: id(l.id) || "link:" + randomUUID().slice(0, 8), title: str(l.title, 60) || "Link", text: str(l.text, 160),
             url, icon: str(l.icon, 500) };
  }).filter((l) => l.url);
  const map = (o, n) => Object.fromEntries(Object.entries(o && typeof o === "object" ? o : {}).filter(([k]) => id(k)).map(([k, v]) => [k, str(v, n)]).filter(([, v]) => v));
  return {
    greeting: str(h.greeting, 60), tagline: str(h.tagline, 80),
    columns: [2, 3].includes(Number(h.columns)) ? Number(h.columns) : 2,
    background: ["grid", "glow", "plain"].includes(h.background) ? h.background : "grid",
    order: (Array.isArray(h.order) ? h.order : []).map(id).filter(Boolean).slice(0, 60),
    hidden: (Array.isArray(h.hidden) ? h.hidden : []).map(id).filter(Boolean).slice(0, 60),
    titles: map(h.titles, 60), texts: map(h.texts, 160), links,
    showBanners: h.showBanners !== false,
  };
}

function savePrefs(p) {
  const patch = {};
  if ("title" in p) patch.title = str(p.title, 40) || "Aegis";
  if ("home" in p) patch.home = p.home === null ? null : cleanHome(p.home);
  if ("login" in p) patch.login = { subtitle: str(p.login?.subtitle, 40) || "Secure channel" };
  if ("sessionDays" in p) patch.sessionDays = Math.max(1, Math.min(365, Math.round(Number(p.sessionDays) || 30)));
  if ("lockout" in p) patch.lockout = { attempts: Math.max(3, Math.min(50, Math.round(Number(p.lockout?.attempts) || 5))),
                                        minutes: Math.max(1, Math.min(1440, Math.round(Number(p.lockout?.minutes) || 15))) };
  if ("modules" in p) {
    const mod = p.modules || {};
    if ("burrow" in mod) burrow.setOn(mod.burrow !== false);
    if ("fleet" in mod) fleet.setEnabled(!!mod.fleet);
  }
  if ("serveo" in p) setServeo(p.serveo !== false);
  if ("autoUpdate" in p) updater.setAuto(!!p.autoUpdate);
  if ("serveoForward" in p) patch.serveoForward = p.serveoForward !== false;
  if ("mounts" in p) {
    const next = { ...(settings.get("mounts") || {}) };
    for (const [id, v] of Object.entries(p.mounts || {})) {
      if (!MOUNTABLE[id]) throw new Error("That app can't be moved.");
      next[id] = cleanMount(v);
    }
    const used = Object.values(next).filter(Boolean);
    if (new Set(used).size !== used.length || used.some((a) => used.some((b) => a !== b && b.startsWith(a + "/")))) throw new Error("Two apps can't share a path.");
    patch.mounts = next;
  }
  settings.set(patch);
}

async function handleApi(req, res, path, url) {
  const mutating = req.method !== "GET";
  if (mutating) {
    // CSRF: a same-origin fetch from our own page, nothing else.
    const o = req.headers.origin;
    let sameOrigin = true;
    try { if (o) sameOrigin = new URL(o).host === req.headers.host; } catch { sameOrigin = false; }
    if (req.headers["x-gate"] !== "1" || !sameOrigin) return sendJson(res, 403, { error: "forbidden" });
  }
  try {
    if (path === "/__gate/api/me") return sendJson(res, 200, me(req));
    if (path === "/__gate/api/notices" && req.method === "GET") return sendJson(res, 200, { notices: noticesLoad().slice(0, 100), ...noticesView() });
    if (path === "/__gate/api/notices/read" && req.method === "POST") {
      const b = await readJsonBody(req), ids = new Set(Array.isArray(b.ids) ? b.ids : []);
      for (const x of noticesLoad()) if (b.all || ids.has(x.id)) x.read = true;
      noticesSave();
      return sendJson(res, 200, { notices: noticesLoad().slice(0, 100), ...noticesView() });
    }
    if (path === "/__gate/api/notices/clear" && req.method === "POST") {
      noticesCache = noticesLoad().filter((x) => !x.read); noticesSave();
      return sendJson(res, 200, { notices: noticesLoad().slice(0, 100), ...noticesView() });
    }
    if (path === "/__gate/api/prefs" && req.method === "POST") { savePrefs(await readJsonBody(req)); return sendJson(res, 200, me(req)); }
    if (path === "/__gate/api/pack" && req.method === "GET") {
      if (!pack.found || Date.now() - pack.found.at > 30000) await pack.detect();
      return sendJson(res, 200, pack.status());
    }
    if (path === "/__gate/api/pack" && req.method === "POST") {
      const body = await readJsonBody(req);
      if (body.skip) { pack.skip(); return sendJson(res, 200, pack.status()); }
      let choice;
      try { choice = await unwrapSealed(body); } catch { return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." }); }
      return sendJson(res, 200, pack.run(choice));
    }
    // Burrow: the tunnel API (burrow/index.mjs)
    // a tunnel's own password comes sealed, like the login (sealedPassword)
    const tunnelBody = async () => {
      const b = await readJsonBody(req);
      // ...and so does the password of a link being cloned (sealedSourcePassword)
      for (const [sealed, field] of [["sealedPassword", "password"], ["sealedSourcePassword", "sourcePassword"]]) {
        if (!b || !b[sealed]) continue;
        try { b[field] = String((await unwrapSealed(b[sealed])).password || ""); }
        catch { throw new Error("Secure handshake failed. Reload and try again."); }
        delete b[sealed];
      }
      return b;
    };
    const apiPath = path.slice("/__gate/api".length);
    const br = await burrow.handle(req.method, apiPath, tunnelBody);
    if (br && req.method !== "GET" && /^\/tunnels/.test(apiPath) && br.status < 400) {
      const t = br.json || {};
      audit(req.method === "POST" && apiPath === "/tunnels" ? "tunnel created" : req.method === "DELETE" ? "tunnel removed" : `tunnel ${apiPath.split("/").slice(2).join("/") || "changed"}`,
            req, { tunnel: t.port || t.removed || apiPath.split("/")[2] || null, ...(t.target ? { target: t.target } : {}), ...(t.access ? { access: t.access } : {}) });
    }
    if (br) return br.body !== undefined ? send(res, br.status, br.body, br.headers) : sendJson(res, br.status, br.json);
    if (path.startsWith("/__gate/api/relay")) {
      const r = await relayRoute(req.method, path.slice("/__gate/api".length), () => readJsonBody(req));
      if (r) { if (req.method !== "GET" && r.status < 400) audit(`relay ${path.split("/").pop()}`, req, {}); return sendJson(res, r.status, r.json); }
    }
    if (path === "/__gate/api/addon" && req.method === "GET") {
      const v = addonView({ tunnels, control: burrow.controlView(), burrow: burrow.status() });
      if (v.forge && !v.addon) v.addon = await forgeHasUs();          // the drop-in may lag the Forge
      return sendJson(res, 200, v);
    }
    if (path.startsWith("/__gate/api/addons") || path.startsWith("/__gate/api/bridge")) return await handleAddons(req, res, path, url);
    const xm = /^\/__gate\/api\/x\/([a-z0-9][a-z0-9-]{1,39})(\/[^?]*)?$/.exec(path);
    if (xm) {
      const r = await extRoute(xm[1], xm[2] || "/", req.method, url.searchParams, () => readJsonBody(req), "dashboard");
      return r.body !== undefined ? send(res, r.status, r.body, { "Content-Type": r.type || "application/octet-stream" }) : sendJson(res, r.status, r.json);
    }

    // integrations
    if (path === "/__gate/api/integrations") return sendJson(res, 200, { integrations: listIntegrations().map((i) => viewOf(i)) });
    const im = /^\/__gate\/api\/integrations\/([a-z0-9-]{1,40})(?:\/(logo|desktops)(?:\/([A-Za-z0-9._-]{1,128})\/(start|stop|restart))?)?$/.exec(path);
    if (im) {
      const integ = getIntegration(im[1]);
      if (!integ) return sendJson(res, 404, { error: "No such integration." });
      if (im[2] === "logo") {
        if (!integ.logo) return send(res, 404, "");
        return send(res, 200, integ.logo, { "Content-Type": "image/svg+xml", "Cache-Control": "private, max-age=3600",
                                            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" });
      }
      if (im[2] === "desktops" && !im[3] && req.method === "GET") {
        if (integ.kind !== "selkies-forge") return sendJson(res, 400, { error: "This integration has no desktops." });
        return sendJson(res, 200, { ...(await forgeDesktops(integ, tunnels)), integration: viewOf(integ) });
      }
      if (im[3] && req.method === "POST") {
        await forgeAction(integ, im[3], im[4]);
        log("integration", integ.id, im[4], im[3]);
        return sendJson(res, 200, { ok: true });
      }
      if (!im[2]) return sendJson(res, 200, viewOf(integ));
    }

    // Cloudflare / domain
    if (path === "/__gate/api/cf" && req.method === "GET") return sendJson(res, 200, cloudflare.state());
    if (path === "/__gate/api/cf/login" && req.method === "POST") return sendJson(res, 200, await cloudflare.startLogin());
    if (path === "/__gate/api/cf/cancel" && req.method === "POST") return sendJson(res, 200, cloudflare.cancelLogin());
    if (path === "/__gate/api/cf/forget" && req.method === "POST") return sendJson(res, 200, cloudflare.forgetCert());
    if (path === "/__gate/api/cf/link" && req.method === "POST") return sendJson(res, 200, await cloudflare.link((await readJsonBody(req)).label));
    if (path === "/__gate/api/cf/unlink" && req.method === "POST") return sendJson(res, 200, await cloudflare.unlink());
    if (path === "/__gate/api/cf/rename" && req.method === "POST") return sendJson(res, 200, await cloudflare.rename((await readJsonBody(req)).label));
    // more domains (burrow/domains.mjs)
    const D = burrow.domains;
    if (path === "/__gate/api/domains" && req.method === "GET") return sendJson(res, 200, D.view());
    if (path === "/__gate/api/domains/login" && req.method === "POST") return sendJson(res, 200, await D.startLogin());
    if (path === "/__gate/api/domains/cancel" && req.method === "POST") return sendJson(res, 200, D.cancelLogin());
    if (path === "/__gate/api/domains/forget" && req.method === "POST") return sendJson(res, 200, D.forget());
    if (path === "/__gate/api/domains/check" && req.method === "POST") return sendJson(res, 200, await D.check((await readJsonBody(req)).zone));
    if (path === "/__gate/api/domains/token" && req.method === "POST") {
      const b = await readJsonBody(req); const r = await D.useToken(b.zone, b.token); audit("Cloudflare token added", req, { zone: r.pending?.zone }); return sendJson(res, 200, r);
    }
    if (path === "/__gate/api/domains" && req.method === "POST") {
      const r = await D.add(await readJsonBody(req)); audit("domain added", req, { zone: r.domains.at(-1)?.zone }); return sendJson(res, 200, r);
    }
    const dm = /^\/__gate\/api\/domains\/([a-z0-9.-]{3,253})$/.exec(path);
    if (dm && req.method === "PATCH") return sendJson(res, 200, await D.update(dm[1], await readJsonBody(req)));
    if (dm && req.method === "DELETE") { const r = await D.remove(dm[1]); audit("domain removed", req, { zone: dm[1] }); return sendJson(res, 200, r); }

    // Updates and the changelogs
    if (path === "/__gate/api/update" && req.method === "GET") return sendJson(res, 200, url.searchParams.has("fresh") ? await updater.fresh() : updater.view());
    if (path === "/__gate/api/update/check" && req.method === "POST") return sendJson(res, 200, await updater.check());
    if (path === "/__gate/api/update/apply" && req.method === "POST") {
      log("update: asked for by", sessionOf(req)?.u || "?");
      const job = await updater.apply();
      return sendJson(res, job.state === "error" ? 500 : 200, { ...updater.view(), job, error: job.error || undefined });
    }
    if (path === "/__gate/api/update/versions" && req.method === "GET") return sendJson(res, 200, await updater.versions());
    if (path === "/__gate/api/update/rollback" && req.method === "POST") {
      const b = await readJsonBody(req);
      log("update: going to", b.version, "asked for by", sessionOf(req)?.u || "?");
      audit("update rollback", req, { to: String(b.version || "").slice(0, 20) });
      const job = await updater.rollback(b.version, { hold: b.hold !== false });
      return sendJson(res, job.state === "error" ? 400 : 200, { ...updater.view(), job, error: job.error || undefined });
    }
    if (path === "/__gate/api/update/hold" && req.method === "POST") {
      const b = await readJsonBody(req);
      updater.setHold(b.version || null);
      return sendJson(res, 200, await updater.versions());
    }
    const cl = /^\/__gate\/api\/changelog\/([a-z-]{1,20})$/.exec(path);
    if (cl && req.method === "GET") return sendJson(res, 200, await updater.changelog(cl[1]));

    // Termix
    if (path === "/__gate/api/termix" && req.method === "GET") return sendJson(res, 200, await termix.status());
    if (path === "/__gate/api/termix/install" && req.method === "POST") return sendJson(res, 200, termix.install());
    if (path === "/__gate/api/termix/remove" && req.method === "POST") return sendJson(res, 200, await termix.remove());

    // machines
    if (path === "/__gate/api/fleet" && req.method === "GET") return sendJson(res, 200, fleetListing());
    if (path.startsWith("/__gate/api/fleet/")) return await handleFleet(req, res, path, url);

    // account
    if (path === "/__gate/api/password" && req.method === "POST") {
      const ip = clientIp(req);
      if (tooManyFails(ip)) return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
      let f;
      try { f = await unwrapSealed(await readJsonBody(req)); } catch { return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." }); }
      if (!checkCredentials(settings.auth().username, f.current)) { recordFail(ip); audit("password change refused", req, { why: "wrong current password" }); return sendJson(res, 401, { error: "The current password is wrong." }); }
      const username = String(f.username || settings.auth().username).trim();
      if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) return sendJson(res, 400, { error: "Username: 2-64 letters, digits, . _ @ -" });
      if (String(f.password || "").length < 10) return sendJson(res, 400, { error: "Use at least 10 characters." });
      setPassword(username, f.password);
      log("password changed from", ip, "- every other session is signed out, every device key forgotten"); audit("password changed", req, { user: username });
      devices.forgetAll(); req._dev = null;
      return sendJson(res, 200, { ok: true }, { "Set-Cookie": [sessionCookie(req, b64u(randomBytes(12))), enrollDevice(req)] });
    }
    if (path === "/__gate/api/audit" && req.method === "GET") return sendJson(res, 200, { events: auditRead(Number(url.searchParams.get("n")) || 300) });
    // your devices
    if (path === "/__gate/api/devices" && req.method === "GET") return sendJson(res, 200, { devices: devices.list(deviceOf(req)) });
    const dvm = /^\/__gate\/api\/devices\/([A-Za-z0-9_-]{8,40})$/.exec(path);
    if (dvm && req.method === "PATCH") { devices.rename(dvm[1], (await readJsonBody(req)).name); return sendJson(res, 200, { devices: devices.list(deviceOf(req)) }); }
    if (dvm && req.method === "DELETE") {
      if (!devices.forget(dvm[1])) return sendJson(res, 404, { error: "No such device." });
      audit("device forgotten", req, { device: dvm[1].slice(0, 6) });
      return sendJson(res, 200, { devices: devices.list(deviceOf(req)) });
    }
    return sendJson(res, 404, { error: "not found" });
  } catch (e) {
    return sendJson(res, 400, { error: e.message });
  }
}

// ---------- Burrow's addons, and the bridge to Selkies Forge ----------

async function handleAddons(req, res, path, url) {
  const ok = (o) => sendJson(res, 200, o);
  try {
    if (path === "/__gate/api/addons" && req.method === "GET") return ok({ addons: await addons.list(), spec: 1, host: "burrow", version: VERSION });
    // what has an update waiting; ?fresh=1 first checks anything not checked in 15 minutes
    if (path === "/__gate/api/addons/updates" && req.method === "GET") {
      if (url.searchParams.get("fresh")) await addons.checkAll(15 * 60e3);
      return ok({ updates: addons.updates() });
    }
    if (path === "/__gate/api/addons/down" && req.method === "GET") return ok({ down: addons.downList() });
    if (path === "/__gate/api/addons/scan" && req.method === "GET") return ok(await addons.scan(url.searchParams.get("fresh") ? 0 : 60000));
    if (path === "/__gate/api/addons/add" && req.method === "POST") return ok({ addon: await addons.add((await readJsonBody(req)).source) });
    if (path === "/__gate/api/addons/inspect" && req.method === "POST") {
      try { return ok(await addons.inspect((await readJsonBody(req)).source)); } catch (e) { return ok({ valid: false, error: e.message }); }
    }
    const j = /^\/__gate\/api\/addons\/jobs\/([0-9a-f]{12})(\/cancel)?$/.exec(path);
    if (j) {
      const job = addons.job(j[1]);
      if (j[2] && req.method === "POST") { job.cancel(); return ok(job.view(1e9)); }
      return ok(job.view(Number(url.searchParams.get("since")) || 0));
    }
    const m = /^\/__gate\/api\/addons\/([a-z0-9-]{2,40})\/(image|install|update|uninstall|rollback|versions|remove|action|check|share|down|autorestart|rescue|reports|report|root)$/.exec(path);
    if (m) {
      const [, id, op] = m;
      if (op === "reports") return ok({ reports: addons.reports(id) });
      // does it need root, and does sudo ask for a password here? (the dialog opens on this)
      if (op === "root") return ok(await addons.rootInfo(id));
      if (op === "versions") return ok(addons.versionsView(id));
      if (op === "report") {
        const file = String(url.searchParams.get("file") || ""), text = addons.report(id, file);
        return send(res, 200, text, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store",
          ...(url.searchParams.get("download") ? { "Content-Disposition": `attachment; filename="${id}-${file}"` } : {}) });
      }
      if (op === "image") { const im = addons.image(id, url.searchParams.get("path")); return send(res, 200, im.body, { "Content-Type": im.type, "Cache-Control": "private, max-age=86400", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" }); }
      if (req.method !== "POST") return sendJson(res, 405, { error: "POST" });
      const b = await readJsonBody(req);
      // install / update / uninstall / an action: root ones need a grant first
      // (b.password when sudo asks; never kept past the job, never logged)
      if (["install", "update", "uninstall", "action", "rollback"].includes(op)) {
        const grant = await addons.rootGrant(id, op, { password: b.password, action: b.action });
        if (grant) audit(`addon: ${op}${op === "action" ? ` ${b.action}` : ""} as administrator (root)`, req, { addon: id });
        const job = addons.runOp(op, id, b, grant);
        if (op === "install" && id === "selkies-forge") followForge(job.id);
        return ok({ job });
      }
      if (op === "remove") return ok(addons.remove(id));
      if (op === "rescue") { audit("addon: start it whatever it takes", req, { addon: id }); return ok({ job: addons.rescue(id) }); }
      if (op === "check") return ok(await addons.checkUpdates(id));
      if (op === "share") return ok({ tunnel: await addons.share(id, b.on !== false, b.access === "public" ? "public" : "login") });
      // it stopped on its own: start it again (maybe always), or leave it off
      if (op === "down") {
        const a = b.start ? addons.startAction(addons.get(id)) : null;
        const grant = a ? await addons.rootGrant(id, "action", { password: b.password, action: a.id }) : null;
        return ok({ job: addons.answerDown(id, { start: !!b.start, always: "always" in b ? !!b.always : undefined }, grant) });
      }
      if (op === "autorestart") return ok(addons.setAutoRestart(id, b.on !== false));
    }
    if (path === "/__gate/api/bridge" && req.method === "GET") return ok(await bridgeHealth({ burrow, addons }));
    const bj = /^\/__gate\/api\/bridge\/job\/([0-9a-f]{4,64})$/.exec(path);
    if (bj) return ok(await forgeJob(bj[1], Number(url.searchParams.get("since")) || 0));
    if (path === "/__gate/api/bridge/connect" && req.method === "POST") {
      const out = { forge: await submitToForge({ log }) };
      const local = await adoptForge({ addons, log }).catch((e) => ({ error: e.message }));
      if (local) out.local = local;
      return ok(out);
    }
    return sendJson(res, 404, { error: "not found" });
  } catch (e) {
    if (e instanceof RootError) return sendJson(res, e.status, { error: e.message, ...e.extra });
    if (!(e instanceof AddonError)) log("addons:", e.message);
    return sendJson(res, 400, { error: e.message });
  }
}

// ---------- machine management (aegis/fleet.mjs, aegis/fleet-ops.mjs) ----------

// What the home page and the chooser need: is it on, how many machines, and
// which of them has an app you may want to open.
function fleetSummary() {
  if (!fleet.enabled()) return { enabled: false, machines: 0, apps: {} };
  const list = fleet.list(), now = Date.now();
  const apps = {};
  for (const m of list) {
    for (const a of (m.probe?.apps || [])) {
      (apps[a.id] ||= []).push({ machine: m.id, name: m.name, address: m.address, url: a.url,
                                 version: a.version, up: machineUp(m, now) });
    }
  }
  return { enabled: true, machines: list.length, standby: list.filter((m) => m.standby).length,
           unreachable: list.filter((m) => !machineUp(m, now)).length, apps, takeover: takeover() };
}

function fleetListing() {
  if (!fleet.enabled()) return { enabled: false, machines: [], hub: fleet.hub(), catalog: fleetCatalog() };
  return { ...fleet.view(), catalog: fleetCatalog(), termix: !!settings.get("termix"), takeover: takeover(),
           here: hereApps() };
}
const fleetCatalog = () => [
  ...Object.entries(FLEET_APPS).map(([id, a]) => ({ id, name: a.name, note: a.note, installable: !!a.install, swappable: !!a.swappable })),
  ...[...addonPrograms()].map(([id, p]) => ({ id, name: p.name, note: p.note || "", installable: true, swappable: false, addon: p.addon })),
];
// What installed addons can put on a linked machine: "<addon>:<program>" -> program.
function addonPrograms() {
  const out = new Map();
  for (const [aid, x] of extensions) {
    if (x.error || !Array.isArray(x.mod.programs)) continue;
    for (const p of x.mod.programs) {
      if (!p || !/^[a-z0-9-]{1,40}$/.test(String(p.id || "")) || typeof p.install !== "function" || !p.name) continue;
      out.set(`${aid}:${p.id}`, { name: String(p.name).slice(0, 60), note: p.note ? String(p.note).slice(0, 300) : "", install: p.install, addon: aid });
    }
  }
  return out;
}

// Where each app on this machine is managed, inside this dashboard.
function manageLinks() {
  const out = { "aegis-burrow": "/__gate/settings" };
  if (settings.get("termix")) out.termix = "/__gate/open/termix";
  if (addons.load().bulwark?.installed) out.bulwark = "/__gate/bulwark/";
  for (const i of listIntegrations()) if (i.kind === "selkies-forge") out["selkies-forge"] = "/__gate/tunnels#/forge";
  return out;
}

// The apps on this machine, in the same shape as a linked machine's, so the
// graph can draw this host like any other.
function hereApps() {
  const out = [{ id: "aegis-burrow", name: FLEET_APPS["aegis-burrow"].name, version: VERSION, url: null }];
  for (const i of listIntegrations()) {
    if (FLEET_APPS[i.kind]) out.push({ id: i.kind, name: i.name, version: i.version, url: i.url });
  }
  if (settings.get("termix")) out.push({ id: "termix", name: "Termix", version: null, url: null });
  if (addons.load().bulwark?.installed) out.push({ id: "bulwark", name: "Bulwark", version: null, url: null });
  return out;
}

async function handleFleet(req, res, path, url) {
  const ok = (o) => sendJson(res, 200, o);
  const rest = path.slice("/__gate/api/fleet/".length);
  try {
    fleet.need();
    const body = req.method === "GET" ? {} : await readJsonBody(req);

    if (rest === "invite" && req.method === "POST") {
      const inv = await fleet.invite({ base: body.base || `${isSecure(req) ? "https" : "http"}://${req.headers.host}`, label: body.label });
      audit("machine: link command made", req, { base: inv.base });
      return ok(inv);
    }
    if (rest === "add" && req.method === "POST") {
      const r = await fleet.addManual(body);
      audit("machine: linked by hand", req, { machine: r.id, address: String(body.address || "").slice(0, 80) });
      return ok({ ...r, machines: fleet.view().machines });
    }
    if (rest === "transfer" && req.method === "POST") {
      if (!body.confirm) return sendJson(res, 400, { error: "A transfer stops the app while its data is copied. Confirm it first." });
      const job = fleetTransfer(fleet, String(body.app || ""), String(body.from || ""), String(body.to || ""), { mode: body.mode === "move" ? "move" : "copy" });
      audit("machine: transfer started", req, { app: body.app, from: body.from, to: body.to, mode: body.mode });
      return ok({ job });
    }
    if (rest === "swap" && req.method === "POST") {
      if (!body.confirm) return sendJson(res, 400, { error: "A swap stops both apps and moves their data. Confirm it first." });
      const job = fleetSwap(fleet, String(body.app || ""), String(body.a || ""), String(body.b || ""));
      audit("machine: swap started", req, { app: body.app, a: body.a, b: body.b });
      return ok({ job });
    }
    if (rest === "self" && req.method === "GET") return ok({ ...(await fleet.selfDetail(!!url.searchParams.get("fresh"))), manage: manageLinks() });
    if (rest.startsWith("jobs/")) return ok(fleet.job(rest.slice(5)).view(Number(url.searchParams.get("since")) || 0));
    if (rest.startsWith("apps/")) return ok({ app: rest.slice(5), where: fleet.whereIs(rest.slice(5)) });

    const m = /^(m-[0-9a-f]{10})(?:\/([a-z]+))?(?:\/([a-z]+))?$/.exec(rest);
    if (!m) return sendJson(res, 404, { error: "not found" });
    const [, id, what, more] = m;

    if (!what && req.method === "GET") return ok(fleet.detail(id));
    if (!what && req.method === "PATCH") return ok(fleet.rename(id, body.name) && fleet.detail(id));
    if (!what && req.method === "DELETE") {
      const role = fleet.get(id).role;
      const r = await fleet.forget(id, url.searchParams.get("keep-key") !== "1");
      if (role === "relay" && relayLink.machine()?.id === id) relayLink.setMachine({ declined: true });      // it stays out until the relay is set up again
      audit("machine: forgotten", req, { machine: id, keyRemoved: r.removed });
      return ok({ ...r, machines: fleet.view().machines });
    }
    if (what === "probe" && req.method === "POST") return ok(fleet.detail((await fleet.probe(id, { fresh: true })).id));
    if (what === "verify" && req.method === "POST") return ok(fleet.detail((await fleet.verify(id)).id));
    if (what === "install" && req.method === "POST") {
      audit("machine: install started", req, { machine: id, app: body.app });
      return ok({ job: fleetInstall(fleet, id, String(body.app || ""), addonPrograms()) });
    }
    if (what === "termix" && req.method === "POST") {
      if (!body.confirm) return sendJson(res, 400, { error: "Adding the machine to Termix needs your say-so first." });
      const r = await toTermix(fleet, termix, id, body);
      audit("machine: added to Termix", req, { machine: id, auth: body.auth === "password" ? "password" : "key" });
      return ok(r);
    }
    if (what === "movegate" && req.method === "POST") {
      if (!body.confirm) return sendJson(res, 400, { error: "Moving this gate hands everything to that machine. Confirm it first." });
      const job = fleetMoveGate(fleet, id, { domain: settings.get("domain"), version: VERSION });
      audit("machine: this gate moving", req, { machine: id });
      standDownAfter(job.id);
      return ok({ job });
    }
    if (what === "standby" && req.method === "POST") {
      if (more === "refresh") return ok({ job: standbyRefresh(fleet, id) });
      if (body.on === false) {
        audit("machine: standby off", req, { machine: id });
        return ok({ job: standbyOff(fleet, id) });
      }
      if (!body.confirm) return sendJson(res, 400, { error: "The standby copies this gate (login included) to that machine. Confirm it first." });
      audit("machine: standby on", req, { machine: id, url: String(body.url || "").slice(0, 120) });
      return ok({ job: standbyOn(fleet, id, body) });
    }
    return sendJson(res, 404, { error: "not found" });
  } catch (e) {
    if (!(e instanceof FleetError)) log("fleet:", e.message);
    return sendJson(res, 400, { error: e.message });
  }
}

// Once the move is done (and only then), this process ends; its supervisor
// starts it again in "moved" mode, serving just the notice.
function standDownAfter(jid) {
  const t = setInterval(() => {
    let j; try { j = fleet.job(jid); } catch { clearInterval(t); return; }
    if (j.state === "running") return;
    clearInterval(t);
    if (j.state === "done" && j.result?.standDown) { log("fleet: moved to another machine; standing down"); setTimeout(() => process.exit(0), 4000); }
  }, 1000);
}
// Just moved in: every installed addon is started whatever it takes (their
// services may not exist on this machine yet), once, and the bell says so.
function settleMoveIn() {
  const f = join(DATA, "moved-in.json");
  if (!existsSync(f)) return;
  let from = "another machine";
  try { from = JSON.parse(readFileSync(f, "utf8")).from || from; } catch { /* fine */ }
  rmSync(f, { force: true });
  notify("fleet", { level: "info", key: "moved-in", title: `This gate moved here from ${from}`, body: "Its login, domain, tunnels, addons and machines came with it. Its addons are being started on this machine.", link: "/__gate/tunnels#/addons" });
  (async () => {
    for (const rec of Object.values(addons.load())) {
      if (!rec.installed) continue;
      try {
        const j = addons.rescue(rec.id);
        while (addons.job(j.id).state === "running") await new Promise((r) => setTimeout(r, 2000));
        log(`moved in: ${rec.id}: ${addons.job(j.id).result?.verdict || addons.job(j.id).error}`);
      } catch (e) { log(`moved in: ${rec.id}:`, e.message); }
    }
  })();
}
setTimeout(settleMoveIn, 15000).unref();

// A clone that took over says so, loudly, on every start and while it keeps
// trying to bring the other host back.
takeoverNotice(notify);
setInterval(() => { try { takeoverNotice(notify); } catch (e) { log("fleet:", e.message); } }, 60000).unref();

// Keep the standby's copy current, a few times a day, quietly.
setInterval(() => {
  if (!fleet.enabled()) return;
  for (const m of fleet.list()) {
    if (!m.standby) continue;
    const age = Date.now() - (m.standbyState?.at || 0);
    if (age < 6 * 3600e3) continue;
    try { standbyRefresh(fleet, m.id); } catch (e) { log("fleet: standby refresh", m.name, e.message); }
  }
}, 30 * 60000).unref();

// Linking Selkies Forge here finishes the bridge from our side too: once that
// job is done, the Forge is asked to add us (if it hasn't).
function followForge(jid) {
  const t = setInterval(() => {
    let job;
    try { job = addons.job(jid); } catch { clearInterval(t); return; }
    if (job.state === "running") return;
    clearInterval(t);
    if (job.state === "done") submitToForge({ log }).catch((e) => log("bridge:", e.message));
  }, 2000);
}

// ---------- apps under a path (Settings → Advanced → Where apps live) ----------
// Off by default: Termix answers at the dashboard's root, Selkies Forge on its
// own address. A mount serves one of them under a path of the dashboard
// instead (/__gate/termix, /forge…), behind the same login. The prefix is cut
// off before the request goes on. Termix is told its base path (its page has a
// <meta name="termix-base-path">); anything a mounted page asks for at an
// absolute path (Forge's /api/…, /app.js) is recognised by its Referer.

const MOUNT_RE = /^\/(?:__gate\/)?[a-z0-9][a-z0-9-]{0,30}$/;
const GATE_WORDS = new Set(["login", "logout", "setup", "settings", "tunnels", "welcome", "api", "open", "sso", "challenge",
                            "health", "logos", "home", "common", "ui"]);
const MOUNTABLE = { termix: "Termix", "selkies-forge": "Selkies Forge" };
function cleanMount(p) {
  if (p == null || p === "") return null;
  p = String(p).trim().toLowerCase().replace(/\/+$/, "");
  if (!p.startsWith("/")) p = "/" + p;
  if (!MOUNT_RE.test(p)) throw new Error("A path is / then 1-31 letters, digits and dashes, like /termix or /__gate/termix.");
  const word = p.split("/").pop();
  if (p.startsWith("/__gate/") && (GATE_WORDS.has(word) || FILES[word] || FILES[word + ".js"] || FILES[word + ".html"])) throw new Error(`/__gate/${word} is Aegis's own.`);
  if (p === "/__gate") throw new Error("/__gate is Aegis's own.");
  return p;
}
function mounts() {
  const want = settings.get("mounts") || {}, out = [];
  const up = (u) => { try { const x = new URL(u); return { https: x.protocol === "https:", host: x.hostname, port: Number(x.port || (x.protocol === "https:" ? 443 : 80)) }; } catch { return null; } };
  if (want.termix && termixUpstream()) out.push({ id: "termix", name: "Termix", prefix: want.termix, up: termixUpstream(), keepHost: true, meta: "termix-base-path" });
  const f = want["selkies-forge"] && listIntegrations().find((i) => i.kind === "selkies-forge" && i.url);
  if (f && up(f.url)) out.push({ id: "selkies-forge", name: "Selkies Forge", prefix: want["selkies-forge"], up: up(f.url), keepHost: false });
  // an addon's own app, under the dashboard's login (Bulwark: /__gate/bulwark)
  for (const [id, x] of extensions) {
    let m = null;
    try { m = typeof x.mod.mount === "function" ? x.mod.mount() : x.mod.mount; } catch { m = null; }
    if (!m?.prefix || !/^\/__gate\/[a-z0-9][a-z0-9-]{1,30}$/.test(m.prefix) || !up(m.upstream)) continue;
    out.push({ id, name: m.name || id, prefix: m.prefix, up: up(m.upstream), keepHost: false, headers: m.headers || null, tile: m.tile || null, commit: x.commit });
  }
  return out;
}
const mountAt = (path) => mounts().find((m) => path === m.prefix || path.startsWith(m.prefix + "/")) || null;
const termixMounted = () => mounts().some((m) => m.id === "termix");
// a request a mounted page made for an absolute path: its Referer says which page
function mountByReferer(req) {
  let u;
  try { u = new URL(req.headers.referer || ""); } catch { return null; }
  if (u.hostname.toLowerCase() !== hostOf(req)) return null;
  return mountAt(u.pathname);
}
function viewOf(integ) {
  const v = publicView(integ, tunnels);
  const m = mounts().find((x) => x.id === integ.kind);
  if (m) Object.assign(v, { dashboard: m.prefix + "/", mounted: m.prefix });
  return v;
}

function proxyMount(m, req, res, upPath) {
  const headers = upstreamHeaders(req);
  if (m.headers) Object.assign(headers, m.headers);
  if (!m.keepHost) {
    // a Forge bound to localhost only answers to its own name, and checks Origin against it
    const upOrigin = `${m.up.https ? "https" : "http"}://${m.up.host}:${m.up.port}`;
    headers.host = `${m.up.host}:${m.up.port}`;
    if (headers.origin) headers.origin = upOrigin;
    if (headers.referer) delete headers.referer;
  }
  const rewrite = !!m.meta && req.method === "GET" && isPageLoad(req);
  if (rewrite) delete headers["accept-encoding"];
  const mod = m.up.https ? httpsRequest : httpRequest;
  const r = mod({ host: m.up.host, port: m.up.port, method: req.method, path: upPath, headers, rejectUnauthorized: false }, (upRes) => {
    const h = { ...upRes.headers, "referrer-policy": "same-origin" };
    const loc = h.location;
    if (typeof loc === "string" && loc.startsWith("/") && !loc.startsWith("//") && !loc.startsWith(m.prefix + "/")) h.location = m.prefix + loc;
    if (rewrite && /text\/html/i.test(h["content-type"] || "")) {
      const chunks = [];
      upRes.on("data", (c) => chunks.push(c));
      upRes.on("end", () => {
        const html = Buffer.concat(chunks).toString("utf8")
          .replace(new RegExp(`(<meta\\s+name="${m.meta}"\\s+content=")[^"]*(")`, "i"), `$1${m.prefix}$2`);
        delete h["content-length"]; delete h["content-encoding"];
        res.writeHead(upRes.statusCode, h);
        res.end(html);
      });
      return;
    }
    res.writeHead(upRes.statusCode, h);
    upRes.pipe(res);
  });
  r.on("error", (e) => { log(`${m.id} upstream error`, e.message); if (!res.headersSent) messagePage(res, 502, `${m.name} is not responding`, "Check it on this machine, or put it back at its own address under Settings → Advanced."); else res.destroy(); });
  req.pipe(r);
}

// ---------- reverse proxy to Termix ----------

function termixUpstream() {
  const t = settings.get("termix");
  if (!t?.upstream) return null;
  const u = new URL(t.upstream);
  return { https: u.protocol === "https:", host: u.hostname, port: Number(u.port || (u.protocol === "https:" ? 443 : 80)) };
}

function upstreamHeaders(req) {
  const h = { ...req.headers };
  const cookie = stripGateCookie(h.cookie);
  if (cookie) h.cookie = cookie; else delete h.cookie;
  h["x-forwarded-for"] = clientIp(req);
  h["x-forwarded-proto"] = isSecure(req) ? "https" : "http";
  h["x-forwarded-host"] = req.headers.host || "";
  return h;
}

function proxy(req, res, extra) {
  const up = termixUpstream();
  if (!up) return send(res, 302, "", { Location: "/" });
  const mod = up.https ? httpsRequest : httpRequest;
  const r = mod({
    host: up.host, port: up.port, method: req.method, path: req.url, headers: upstreamHeaders(req),
    rejectUnauthorized: false, // Termix's own self-signed cert, on this machine
  }, (upRes) => {
    const headers = { ...upRes.headers };
    if (extra?.setCookie) headers["set-cookie"] = [...[].concat(headers["set-cookie"] || []), ...[].concat(extra.setCookie)];
    res.writeHead(upRes.statusCode, headers);
    upRes.pipe(res);
  });
  r.on("error", (e) => { log("termix upstream error", e.message); if (!res.headersSent) messagePage(res, 502, "Termix is not responding", "Check it under Settings → Termix."); else res.destroy(); });
  req.pipe(r);
}

function proxyUpgrade(req, socket, head, up = termixUpstream(), path = req.url, headers = upstreamHeaders(req)) {
  if (!up) { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }
  const mod = up.https ? httpsRequest : httpRequest;
  const r = mod({ host: up.host, port: up.port, method: req.method, path, headers, rejectUnauthorized: false });
  r.on("upgrade", (upRes, upSocket, upHead) => {
    const lines = [`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}`];
    for (let i = 0; i < upRes.rawHeaders.length; i += 2) lines.push(`${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}`);
    socket.write(lines.join("\r\n") + "\r\n\r\n");
    if (upHead?.length) socket.write(upHead);
    if (head?.length) upSocket.write(head);
    upSocket.pipe(socket).pipe(upSocket);
    upSocket.on("error", () => socket.destroy());
    socket.on("error", () => upSocket.destroy());
  });
  r.on("response", (upRes) => { socket.end(`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n\r\n`); });
  r.on("error", () => socket.destroy());
  r.end();
}

// A top-level page load (typing the address, a link, a reload), not a fetch
// or an iframe. Termix's service worker re-fetches page loads itself, and
// those arrive as mode "navigate" with dest "empty", so either one counts.
function isPageLoad(req) {
  const dest = req.headers["sec-fetch-dest"], mode = req.headers["sec-fetch-mode"];
  if (dest || mode) return dest === "document" || mode === "navigate";
  return (req.headers.accept || "").includes("text/html");
}

// ---------- tunnel hosts ----------

function notFoundPage(res, why) {
  messagePage(res, why === "paused" ? 503 : 404, why === "paused" ? "This tunnel is paused" : "No tunnel here",
              why === "paused" ? "Its owner switched it off for now." : "Nothing is published on this address.");
}

async function tunnelRequest(port, req, res, path, url, host) {
  const t = tunnels.get(port);
  if (!t) return notFoundPage(res, "none");
  if (path === "/__gate/unlock" && t.access === "password" && t.enabled) return unlockRoute(t, req, res, url, host);
  if (path === "/__gate/burrow" && req.method === "GET") return burrowInfo(t, res, host);
  if (path === "/__gate/clone" && t.access === "password" && t.enabled) return cloneRoute(t, req, res, host);
  if (path.startsWith("/__gate/")) return handleGate(req, res, path, url, host, false);
  if (!t.enabled) return notFoundPage(res, "paused");
  if (!mayOpen(req, t)) {
    // x-burrow-gate: a clone of this tunnel learns it was turned away, and why
    const why = { "X-Burrow-Gate": t.access === "password" ? "password" : "login" };
    const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
    if (!wantsHtml) return sendJson(res, 401, { error: t.access === "password" ? "password required" : "login required" }, why);
    const next = encodeURIComponent(safeNext(req.url, "/"));
    if (t.access === "password") return send(res, 302, "", { Location: "/__gate/unlock?next=" + next, ...why });
    return send(res, 302, "", { Location: mainHost() ? ssoUrl(host, req.url) : "/__gate/login?next=" + next, ...why });
  }
  tunnels.proxy(port, req, res, { stripCookie: stripGateCookie });
}

// ---------- server ----------

// A request the Worker front handed over (burrow/workerfront.mjs): it came
// through the dashboard's own tunnel, for a tunnel's name.
function frontClaim(req) {
  if (req.headers["x-aegis-front-key"] === undefined) return;
  const f = tunnels.front.claim(req, isThisMachine(req.socket.remoteAddress));
  if (!f) { req.headers.host = "front.invalid"; return; }
  tunnels.countFront();                 // against Cloudflare's daily limit (Settings → Domain shows it)
  req.headers.host = f.host;
  if (f.ip) req.headers["cf-connecting-ip"] = f.ip;
}

// The shield (burrow/shield.mjs) on every request, before anything else:
// banned addresses, blocklisted ones and payloads stop here. The main host's
// sign-in stays open to everyone (it is throttled), so you can never lock
// yourself out: signing in lifts a ban on your address.
const SIGN_IN_PATHS = new Set(["/__gate/login", "/__gate/login.css", "/__gate/login.js", "/__gate/logos/aegis-burrow.svg", "/__gate/challenge", "/__gate/auth"]);
function shieldStop(req, path, host) {
  const isMain = isDashHost(host);
  if (isMain && SIGN_IN_PATHS.has(path)) return null;
  const ip = clientIp(req);
  // one of your devices (its device key): yours for sure, whatever the address
  const dev = deviceOf(req);
  if (dev) devices.seen(dev, { ip, ua: req.headers["user-agent"], host });
  if (guardExt) {
    const H = req.headers, port = burrow.matchHost(host);
    const info = { t0: Date.now(), method: req.method, path: req.url, host, country: String(H["cf-ipcountry"] || ""), ua: H["user-agent"] || "",
                   referer: H.referer || "", lang: String(H["accept-language"] || "").split(",")[0], ray: H["cf-ray"] || "", proto: req.httpVersion,
                   via: H["x-aegis-front-host"] !== undefined ? "worker" : viaProxy(req) ? (H["cf-ray"] ? "cloudflare" : "relay") : viaServeo(req) ? "serveo" : "direct",
                   port, access: port !== null ? tunnels.get(port)?.access || "login" : null, main: isMain, device: dev, trusted: () => !!dev || isAuthed(req) };
    req._guard = { ip, info, bytes0: req.socket?.bytesWritten || 0 };
    try { return guardExt.guard(ip, info); } catch (e) { log("shield addon:", e.message); return null; }
  }
  return burrow.shield.gate(ip, { method: req.method, path: req.url, host, country: String(req.headers["cf-ipcountry"] || ""), trusted: () => !!dev || isAuthed(req) });
}
// the guard addon's log line, once the response is done (never in the request's way)
function observeDone(req, res, extra = {}) {
  const g = req._guard;
  if (!g || !guardExt?.observe) return;
  try { guardExt.observe(g.ip, g.info, { status: extra.status ?? res?.statusCode ?? 0, bytes: Math.max(0, (req.socket?.bytesWritten || 0) - g.bytes0), ms: Date.now() - g.info.t0 }); }
  catch { /* never in the way */ }
}

async function handler(req, res) {
  res.req = req;
  frontClaim(req);
  const host = hostOf(req);
  const url = new URL(req.url || "/", "http://x");
  const path = url.pathname;
  try {
    // a relay (Caddy with on-demand TLS, on a server of yours) asks before it
    // fetches a certificate for a tunnel name; only this machine may ask
    if (path === "/__gate/relay-ask" && isThisMachine(req.socket.remoteAddress)) {
      const name = String(url.searchParams.get("domain") || "").toLowerCase();
      return send(res, burrow.on && tunnels.relayAsk(name) ? 200 : 404, "");
    }
    const stop = shieldStop(req, path, host);
    if (req._guard) res.once("close", () => observeDone(req, res));
    if (stop) {
      // the guard's own page for a person (checking: it reloads by itself; blocked), plain text for anything else
      if (stop.page && /text\/html/.test(req.headers.accept || "")) {
        return send(res, stop.status, visitorPage(stop.page, { ip: clientIp(req), retry: stop.retry }), { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
          "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'", ...(stop.retry ? { "Retry-After": String(stop.retry) } : {}) });
      }
      return send(res, stop.status, stop.body, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", Connection: "close", ...(stop.retry ? { "Retry-After": String(stop.retry) } : {}) });
    }
    const port = burrow.matchHost(host);
    if (port !== null) return await tunnelRequest(port, req, res, path, url, host);
    // Once a domain is linked, the serveo link forwards page loads to it,
    // carrying a signed-in session along (a 60 s single-use ticket).
    if (host === serveo.host() && mainHost() && serveoForward() && req.method === "GET" && isPageLoad(req)) {
      const s = sessionOf(req), next = safeNext(req.url, "/");
      return send(res, 302, "", { Location: s ? `https://${mainHost()}/__gate/sso/callback?t=${sealTicket(mainHost(), s.sid)}&next=${encodeURIComponent(next)}`
                                               : `https://${mainHost()}${next}` });
    }
    const isMain = isDashHost(host);
    if (!isMain) return send(res, 404, "Not found");
    // an app served under a path of the dashboard (it may live under /__gate/ too)
    const mount = settings.auth() ? mountAt(path) : null;
    if (mount) {
      if (!isAuthed(req)) {
        const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
        return wantsHtml ? send(res, 302, "", { Location: "/__gate/login?next=" + encodeURIComponent(safeNext(req.url, "/")) })
                         : sendJson(res, 401, { error: "login required" });
      }
      if (path === mount.prefix) return send(res, 302, "", { Location: mount.prefix + "/" + url.search });
      return proxyMount(mount, req, res, req.url.slice(mount.prefix.length) || "/");
    }
    if (path.startsWith("/__gate/")) return await handleGate(req, res, path, url, host, true);
    if (!settings.auth()) return send(res, 302, "", { Location: "/__gate/setup" + url.search });
    if (!isAuthed(req)) {
      const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
      if (path !== "/" && termixUpstream()) audit("termix refused: not signed in", req, { path: path.slice(0, 120), quiet: true });
      return wantsHtml
        ? send(res, 302, "", { Location: "/__gate/login" + (path === "/" ? "" : "?next=" + encodeURIComponent(safeNext(req.url, "/"))) })
        : sendJson(res, 401, { error: "login required" });
    }
    // a page load: the session renewed when due, and a device key for a signed-in browser that has none yet
    const renew = req.method === "GET" && isPageLoad(req) ? [renewalCookie(req), deviceOf(req) ? null : enrollDevice(req)].filter(Boolean) : [];
    const withRenew = renew.length ? { "Set-Cookie": renew } : {};
    // what a mounted app's page asks for at an absolute path
    const byRef = path !== "/" ? mountByReferer(req) : null;
    if (byRef) return proxyMount(byRef, req, res, req.url);
    if (!termixUpstream() || termixMounted()) {
      if (path === "/" && req.method === "GET") return page(res, "home.html", withRenew);
      return send(res, 302, "", { Location: "/" });
    }
    if (path === "/" && req.method === "GET" && isPageLoad(req)) {
      if (parseCookies(req.headers.cookie)[goName(req)] !== "termix") return page(res, "home.html", withRenew);
      audit("termix opened", req);
      return proxy(req, res, { setCookie: [`${goName(req)}=; ${cookieAttrs(req, 0)}`, ...renew] });
    }
    proxy(req, res, renew.length ? { setCookie: renew } : undefined);
  } catch (e) {
    log("handler error", e.message);
    if (!res.headersSent) send(res, 500, "Internal error"); else res.destroy();
  }
}

function tlsOptions() {
  const base = { key: readFileSync(TLS.key), cert: readFileSync(TLS.cert), minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
                 ciphers: "TLS_AES_256_GCM_SHA384" };   // AES-256-GCM only
  // post-quantum hybrid key exchange (OpenSSL 3.5+, Node 24+); X25519 on older builds
  for (const ecdhCurve of ["X25519MLKEM768", "X25519"]) {
    try { createHttpsServer({ ...base, ecdhCurve }).close(); return { ...base, ecdhCurve }; } catch { /* try the next */ }
  }
  return base;
}

const server = TLS ? createHttpsServer(tlsOptions(), handler) : createHttpServer(handler);

server.on("upgrade", (req, socket, head) => {
  frontClaim(req);
  const host = hostOf(req);
  // a linked machine's agent (signed per machine; nothing else is answered there)
  if (isDashHost(host) && fleet.enabled() && fleetAgents.handleUpgrade(req, socket, head)) return;
  const stop = shieldStop(req, new URL(req.url || "/", "http://x").pathname, host);
  if (req._guard) { req._guard.info.ws = true; observeDone(req, null, { status: stop ? stop.status : 101 }); }
  if (stop) { socket.end(`HTTP/1.1 ${stop.status} ${stop.status === 403 ? "Forbidden" : "Not Found"}\r\nConnection: close\r\n\r\n`); return; }
  const port = burrow.matchHost(host);
  if (port !== null) {
    const t = tunnels.get(port);
    if (!t || !t.enabled) { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }
    if (!mayOpen(req, t)) { socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n"); return; }
    return tunnels.proxyUpgrade(port, req, socket, head, { stripCookie: stripGateCookie });
  }
  if (!isDashHost(host) || !isAuthed(req)) {
    if (termixUpstream()) audit("termix connection refused: not signed in", req, { path: String(req.url || "").slice(0, 120), quiet: true });
    socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n"); return;
  }
  const m = mountAt(new URL(req.url || "/", "http://x").pathname);
  if (m) {
    const headers = upstreamHeaders(req);
    if (!m.keepHost) { headers.host = `${m.up.host}:${m.up.port}`; delete headers.origin; }
    return proxyUpgrade(req, socket, head, m.up, req.url.slice(m.prefix.length) || "/", headers);
  }
  if (termixMounted()) { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }
  audit("termix connection", req, { path: String(req.url || "").split("?")[0].slice(0, 120) });
  proxyUpgrade(req, socket, head);
});

// ---------- the edge ----------
// Only tunnel names get through here: never the dashboard, whatever the Host
// says, and the client's address is the socket's (headers that claim another
// are dropped).
function edgeAdmit(req) {
  if (burrow.matchHost(hostOf(req)) === null) return false;
  for (const k of ["x-forwarded-for", "x-real-ip", "x-forwarded-proto", "x-forwarded-host"]) delete req.headers[k];
  const relayed = isLoopback(req.socket.remoteAddress) ? relayedFrom.get(req.socket.remotePort) : null;
  req.headers["cf-connecting-ip"] = relayed || String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  return true;
}
// The relay's passthrough: a relay server (Caddy with layer4) can pass the
// encrypted bytes of tunnel names here unopened, so this machine's
// certificate is the one the browser sees and the relay reads nothing. It
// reaches this loopback port through a reverse SSH tunnel and puts a PROXY
// protocol header first, which says who the visitor is.
const RELAY_PORT = Number(process.env.AEGIS_EDGE_RELAY_PORT || EDGE.relayPort || 4443);
// (The rest is handed to the edge's own port over loopback: the TLS server
// reads sockets natively, so bytes already read can't be given back to it.)
const relayedFrom = new Map();          // our loopback port toward the edge -> the visitor's address
const relayIn = createNetServer((sock) => {
  if (!isLoopback(sock.remoteAddress) || !edgeServer?.listening) return sock.destroy();
  sock.on("error", () => {});
  readProxyHeader(sock).then(({ src }) => {
    const up = netConnect(tunnels.edge.port, "127.0.0.1", () => {
      const lp = up.localPort;
      if (src) { relayedFrom.set(lp, src); up.once("close", () => relayedFrom.delete(lp)); }
      sock.pipe(up); up.pipe(sock);
    });
    up.on("error", () => sock.destroy());
    sock.on("close", () => up.destroy());
  }).catch(() => sock.destroy());
});
relayIn.on("error", (e) => log(`edge: the relay port 127.0.0.1:${RELAY_PORT}:`, e.message));
relayIn.listen(RELAY_PORT, "127.0.0.1");
let edgeServer = null;
function edgeListen() {
  if (edgeServer || !tunnels.edge.ready()) return;
  edgeServer = createHttpsServer({
    SNICallback: (name, cb) => { const ctx = tunnels.edge.context(name); if (ctx) cb(null, ctx); else cb(new Error("not a tunnel name")); },
    minVersion: "TLSv1.2",
  }, (req, res) => {
    // the edge's check from the outside (through Cloudflare): answer with its token
    if (hostOf(req) === tunnels.edge.checkName) {
      const ok = new URL(req.url || "/", "http://x").pathname === CHECK_PATH;
      res.writeHead(ok ? 200 : 404, { "Content-Type": "text/plain", "Cache-Control": "no-store" });
      return res.end(ok ? tunnels.edge.checkToken : "");
    }
    if (edgeAdmit(req)) return handler(req, res);
    res.writeHead(421, { "Content-Type": "text/plain" }); res.end("Misdirected request");
  });
  edgeServer.on("upgrade", (req, socket, head) => {
    if (edgeAdmit(req)) server.emit("upgrade", req, socket, head);
    else socket.end("HTTP/1.1 421 Misdirected Request\r\n\r\n");
  });
  edgeServer.on("tlsClientError", () => { /* scanners, names we don't serve */ });
  edgeServer.keepAliveTimeout = 65000;
  const srv = edgeServer;
  let i = 0;
  const fail = (e) => {
    if (srv !== edgeServer) return;
    if (i + 1 < EDGE_PORTS.length && (e.code === "EACCES" || e.code === "EADDRINUSE")) { i++; return srv.listen(EDGE_PORTS[i], EDGE.host); }
    log(`edge: can't listen on ${EDGE.host}:${EDGE_PORTS[i]}:`, e.message);
    edgeServer = null;
  };
  srv.on("error", fail);
  srv.once("listening", () => {
    srv.off("error", fail);
    srv.on("error", (e) => log("edge:", e.message));
    const port = srv.address().port;
    if (tunnels.edge.port !== port) { tunnels.edge.port = port; tunnels.edge.upnp.at = 0; }
    log(`edge: wildcard tunnels answer on ${EDGE.host}:${port} with this machine's certificate`);
  });
  srv.listen(EDGE_PORTS[0], EDGE.host);
}
// ---------- Aegis Relay (burrow/relaylink.mjs) ----------
// The relay listener: 127.0.0.1:RELAY_LINK_PORT, reached only through the SSH
// link (VPS 127.0.0.1:18452 -> here). Plain HTTP inside post-quantum SSH; every
// request must carry the agent's signature, else it never reaches anything.
// It, and the link, run only while the tunnels really go through the relay.
const relayLink = new RelayLink({ dataDir: DATA, log });
const RELAY_LINK_PORT = Number(process.env.AEGIS_RELAY_LINK_PORT || EDGE.relayLinkPort || 4302);
const relayRefused = new Map();
let relayDoctor = null;                  // burrow/relaydoctor.mjs, below
let relayMachineBusy = false;            // linking the VPS into Machines (relayMachine below)
// -> "ok", "unsigned" (no valid signature: a wrong key, or clocks too far apart)
// or "unknown" (signed, but no tunnel has that name)
function relayAdmit(req) {
  const host = hostOf(req);
  for (const k of ["cf-connecting-ip", "x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-aegis-front-host", "x-aegis-front-ip", "x-aegis-front-key"]) delete req.headers[k];
  const ip = relayLink.verifyRequest(req, host);
  delete req.headers["x-aegis-relay"]; delete req.headers["x-aegis-relay-ip"];
  if (!ip) {
    const k = String(req.socket.remotePort), last = relayRefused.get(k) || 0;
    if (Date.now() - last > 60000) { relayRefused.set(k, Date.now()); log("relay: refused a request without a valid signature for", host || "(no host)"); relayDoctor?.soon("a request arrived unsigned"); }
    if (relayRefused.size > 1000) relayRefused.clear();
    return "unsigned";
  }
  if (burrow.matchHost(host) === null) return "unknown";
  req.headers["cf-connecting-ip"] = ip;
  req.headers["x-forwarded-proto"] = "https";
  return "ok";
}
const relayRefuse = (res, why, host) => {
  res.writeHead(why === "unknown" ? 404 : 403, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Aegis-Relay": why === "unknown" ? "no-tunnel" : "bad-signature" });
  res.end(why === "unknown" ? `No tunnel is called ${host} here.` : "Not signed by your relay.");
};
const relayServer = createHttpServer((req, res) => {
  // the agent met someone new at a public tunnel: scan them first in line (their request stayed on the VPS)
  if (req.url === "/__aegis-relay/scan" && req.method === "POST") {
    const ip = String(req.headers["x-aegis-relay-ip"] || "");
    const ok = relayLink.configured() && isIP(ip) && relayVerify(relayLink.keyBuf(), req.headers["x-aegis-relay"], { host: "scan", ip, method: "POST", url: req.url }, relayLink.agentNow());
    if (ok) { try { guardExt?.scan?.(ip); } catch { /* the addon's business */ } }
    res.writeHead(ok ? 204 : 403); return res.end();
  }
  // the relay doctor's ping (burrow/relaydoctor.mjs): any name under a zone the VPS carries, through
  // the whole way a visitor's request takes; it echoes the nonce it was sent and nothing else
  if (req.url.startsWith("/__aegis-relay/ping?")) {
    const host = hostOf(req), why = relayAdmit(req);
    if (why === "unsigned") return relayRefuse(res, why, host);
    const n = /[?&]n=([A-Za-z0-9_-]{8,40})(?:&|$)/.exec(req.url)?.[1] || "";
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Aegis-Relay": "ok" });
    return res.end(JSON.stringify({ n, at: Date.now() }));
  }
  const why = relayAdmit(req);
  if (why === "ok") return handler(req, res);
  relayRefuse(res, why, hostOf(req));
});
relayServer.on("upgrade", (req, socket, head) => {
  if (relayAdmit(req) === "ok") server.emit("upgrade", req, socket, head);
  else socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
});
relayServer.keepAliveTimeout = 65000;
relayServer.on("error", (e) => log(`relay: 127.0.0.1:${RELAY_LINK_PORT}:`, e.message));
const relayWanted = () => {
  const n = tunnels.naming, v = relayLink.state.vps;
  if (!relayLink.configured() || !burrow.on || !v) return false;
  if (burrow.domains.wantsRelay()) return true;            // another domain's tunnels go through the VPS
  if (!tunnels.domain || n.mode !== "wildcard" || n.relay !== v.host) return false;
  return n.certs === "relay" || (n.certs === "self" && (n.route === "vps" || tunnels.edge.target()?.via === "relay"));
};
const relayListen = () => relayServer.listening ? Promise.resolve() : new Promise((resolve, reject) => {
  const fail = (e) => reject(new Error(`the relay listener (127.0.0.1:${RELAY_LINK_PORT}) couldn't start: ${e.message}`));
  relayServer.once("error", fail);
  relayServer.listen(RELAY_LINK_PORT, "127.0.0.1", () => { relayServer.off("error", fail); resolve(); });
});
// Bring the link up (if it isn't), wait for the agent to answer through it,
// and leave it running only if the tunnels use it. -> {ok, error}
async function verifyRelay(ms = 30000) {
  if (!relayLink.configured()) return { ok: false, error: "no relay agent is registered" };
  try { await relayListen(); } catch (e) { return { ok: false, error: e.message }; }
  const v = await relayLink.verify(RELAY_LINK_PORT, ms);
  superviseRelay();
  return v;
}
// Before the tunnels move to the VPS: the agent there is linked and checked,
// and holds this machine's certificate (else nothing moves).
tunnels.beforeVps = async (naming) => {
  const v = relayLink.state.vps;
  if (!relayLink.configured() || v?.host !== naming.relay) throw new Error(`Link ${naming.relay} first: run the install command on it (Settings → Domain → Your VPS).`);
  await relayListen();
  const r = await relayLink.verify(RELAY_LINK_PORT, 30000);
  if (!r.ok) { superviseRelay(); throw new Error(`Couldn't reach the agent on ${v.host}: ${r.error}. Nothing was moved.`); }
  try { await relayLink.pushCert(tunnels.edge.cur); }
  catch (e) { throw new Error(`${v.host} didn't take the certificate (${e.message}). Nothing was moved.`); }
  if (!relayLink.agent?.cert) throw new Error(`${v.host} has no certificate yet. Nothing was moved.`);
};
function superviseRelay() {
  if (relayLink.verifying || relayMachineBusy) return;
  const want = relayWanted();
  if (want && !relayServer.listening) relayServer.listen(RELAY_LINK_PORT, "127.0.0.1", () => relayLink.start(RELAY_LINK_PORT));
  else if (want && !relayLink.running()) relayLink.start(RELAY_LINK_PORT);
  else if (!want && (relayServer.listening || relayLink.running())) {
    relayLink.stop();
    if (relayServer.listening) relayServer.close();
    log("relay: not in use; the link and the relay listener are off");
  }
}
// the certificate to the agent: when the link comes up, when it renews, and hourly (if it differs)
// the link came up: an older agent gets this Aegis's first (1.1+ take it over the link), then the certificates
async function relayUp() {
  if (relayLink.outdated() === "update") await relayLink.updateAgent().catch((e) => log("relay: couldn't update the agent:", e.message));
  else if (relayLink.outdated() === "reinstall" && burrow.domains.wantsRelay()) log(`relay: the agent on ${relayLink.state.vps.host} is ${relayLink.agent.version}; other domains need ${AGENT_VERSION}: run the install command once more`);
  if (tunnels.edge.cur) await relayLink.pushCert(tunnels.edge.cur).catch((e) => log("relay: couldn't push the certificate:", e.message));
  await burrow.domains.pushAll();
  await relayMachine();
}
// The VPS is a machine too. Its agent (1.4+) runs the usual link script there as
// root, so it shows up in Machines with no second command, whether it was added
// for the wildcard tunnels or for anything else. Forgetting it in Machines keeps
// it out; a failure is tried again after six hours. bringUp: start the link for
// it when the tunnels don't use it (it goes off again after).
async function relayMachine({ bringUp = false } = {}) {
  const v = relayLink.state.vps, had = relayLink.machine();
  if (relayMachineBusy || !relayLink.configured() || !v || !mainHost()) return;
  if (had?.declined || (had?.failedAt && Date.now() - had.failedAt < 6 * 3600e3)) return;
  if (had?.id && fleet.list().some((m) => m.id === had.id)) return;
  if ((settings.get("fleet") || {}).enabled === false) return;          // Machines switched off on purpose
  const known = fleet.list().find((m) => m.role === "relay" || m.address === v.host || (m.candidates || []).includes(v.host));
  if (known) { relayLink.setMachine({ id: known.id }); return; }
  if (relayLink.link.state !== "up" && !bringUp) return;
  relayMachineBusy = true;
  const started = Date.now();
  try {
    if (relayLink.link.state !== "up") {
      await relayListen();
      if (!(await relayLink.verify(RELAY_LINK_PORT, 30000)).ok) return;
    }
    if (relayLink.outdated() === "update") await relayLink.updateAgent();
    if (!relayLink.can("fleet")) { log(`relay: the agent on ${v.host} is ${relayLink.agent?.version || "unknown"}; it needs ${AGENT_VERSION} to show up in Machines by itself: run its install command once more`); relayLink.setMachine({ failedAt: Date.now(), error: "agent too old" }); return; }
    if (!fleet.enabled()) fleet.setEnabled(true);
    const inv = await fleet.invite({ base: `https://${mainHost()}`, role: "relay", prefer: v.host });
    log(`relay: linking ${v.host} into Machines`);
    const r = await relayLink.linkMachine(fleet.rootJoinScript(inv.token, inv.base));
    const m = fleet.list().find((x) => x.role === "relay" && x.addedAt >= started);
    if (m) {
      relayLink.setMachine({ id: m.id });
      log(`relay: ${v.host} is in Machines as ${m.name} (${m.user})`);
    } else {
      fleet.dropPending(inv.token);
      const why = String(r.out || "").trim().split("\n").filter(Boolean).slice(-2).join(" / ").slice(0, 300) || `exit ${r.code}`;
      relayLink.setMachine({ failedAt: Date.now(), error: why });
      log(`relay: ${v.host} couldn't link into Machines: ${why}`);
      notify("fleet", { level: "warn", key: "relay-machine", title: "Your VPS isn't in Machines yet",
                        body: `${v.host} ran the link script but didn't come back: ${why}. Aegis tries again in six hours, or use Link a machine.`, link: "/__gate/tunnels#/machines" });
    }
  } catch (e) {
    relayLink.setMachine({ failedAt: Date.now(), error: e.message });
    log(`relay: couldn't link ${v.host} into Machines:`, e.message);
  } finally { relayMachineBusy = false; superviseRelay(); }
}
setTimeout(() => relayMachine({ bringUp: true }).catch(() => {}), 90000).unref();
relayLink.onUp = () => { relayUp().catch(() => {}).finally(() => standby.tick().catch(() => {})); };
setInterval(() => { if (relayLink.link.state === "up") relayLink.control("GET", "/status").then((s) => { relayLink.agent = { ...s, at: Date.now() }; return relayUp(); }).catch(() => {}); }, 3600e3).unref();
// other domains through your VPS (burrow/domains.mjs): the link, its address, its agent
burrow.domains.useRelay({
  configured: () => relayLink.configured(),
  host: () => relayLink.state.vps?.host || null,
  version: () => relayLink.agent?.version || null,
  outdated: () => relayLink.outdated(),
  ip: async () => { const h = relayLink.state.vps?.host; if (!h) throw new Error("no VPS"); if (isIP(h)) return h; const { address } = await dnsLookup(h); return address; },
  ready: async () => {
    const v = await verifyRelay();
    if (!v.ok) return v;
    if (relayLink.outdated() === "update") await relayLink.updateAgent();
    if (!relayLink.can("zones")) return { ok: false, error: `its agent is ${relayLink.agent?.version || "too old"} and needs ${AGENT_VERSION} for more domains: run the install command on it once more (Settings → Domain → Your VPS)` };
    return v;
  },
  push: (cur, suffix) => relayLink.pushCert(cur, suffix),
  remove: (suffix) => relayLink.removeZone(suffix),
});
burrow.onDomainsChange = () => superviseRelay();
// Public tunnels, checked on the VPS first (agent 1.2+): which names are public, and
// who may pass, mirrored from the guard addon (Bulwark) whenever it changes.
let edgeLast = null, edgeBusy = false, edgeWait = 0;
function publicHosts() {
  const out = new Set();
  for (const t of tunnels.list()) {
    if (t.access !== "public" || !t.enabled) continue;
    if (t.host) out.add(t.host.toLowerCase());
    for (const a of t.also || []) if (!a.hidden) out.add(a.host.toLowerCase());
  }
  return [...out].sort();
}
setInterval(async () => {
  if (edgeBusy || Date.now() < edgeWait || relayLink.link.state !== "up" || !relayLink.can("edge")) return;
  const hosts = publicHosts(), ver = guardExt?.edgeVersion?.() ?? -1;
  const key = `${ver}|${hosts.join(",")}|${relayLink.agent?.edge?.epoch || ""}`;
  if (key === edgeLast) return;
  edgeBusy = true;
  try {
    const e = guardExt?.edge?.() || null;
    // without a guard addon nothing is checked there (the built-in shield still works here)
    const want = e ? { on: !!e.on, hosts, cleared: e.cleared, banned: e.banned } : { on: false, hosts, cleared: [], banned: [] };
    await relayLink.syncEdge(want);
    edgeLast = `${ver}|${hosts.join(",")}|${relayLink.agent?.edge?.epoch || ""}`;
  } catch (err) { log("relay: couldn't update who may pass on the VPS:", err.message); edgeLast = null; edgeWait = Date.now() + 30e3; }
  finally { edgeBusy = false; }
}, 1000).unref();
setInterval(superviseRelay, 20000).unref();
setTimeout(superviseRelay, 8000).unref();

// A tunnel's fallback (burrow/standby.mjs): the relay agent stands in while this
// machine, or the tunnel's target, doesn't answer. Only where the VPS carries it.
function standbyHosts(t) {
  const zones = (relayLink.agent?.zones || []).map((z) => z.suffix).filter(Boolean);
  const all = [tunnels.hostFor(t.port), ...tunnels.alsoFor(t).filter((a) => !a.hidden).map((a) => a.host)].filter(Boolean).map((h) => h.toLowerCase());
  if (!zones.length) return all.slice(0, 1);             // the agent not met yet: its zones come with the link
  return [...new Set(all.filter((h) => zones.some((z) => h.endsWith(z) && h.length > z.length && !h.slice(0, -z.length).includes("."))))].slice(0, 8);
}
function standbyWhy(t) {
  if (!relayLink.configured()) return "Your tunnels don't go through a VPS of yours (Settings → Domain → Your VPS). The fallback lives on that VPS, so there's nowhere to keep it.";
  if (!relayWanted()) return "Your tunnels don't go through your VPS right now (Settings → Domain → Your VPS): the fallback is served from there.";
  if (relayLink.agent?.zones && !standbyHosts(t).length) return "This tunnel's address isn't one your VPS carries, so the VPS can't stand in for it.";
  if (relayLink.agent?.version && !relayLink.can("standby") && relayLink.outdated() === "reinstall") return `The agent on ${relayLink.state.vps.host} is ${relayLink.agent.version} and can't update itself: run its install command once more (Settings → Domain → Your VPS) to get fallbacks.`;
  return null;
}
const standby = new Standby({ tunnels, link: relayLink, log, eligible: standbyWhy, hostsOf: standbyHosts });
burrow.standby = standby;
standby.start();
// The relay doctor: checks the way in from the outside (HTTPS to the VPS, a name
// of ours, back through the link to this gate) and fixes what it can.
relayDoctor = new RelayDoctor({
  link: relayLink, dataDir: DATA, log, wanted: relayWanted, bringUp: () => verifyRelay(),
  zones: () => {
    const z = (relayLink.agent?.zones || []).map((x) => x.suffix).filter(Boolean);
    return z.length ? z : tunnels.wildcard ? ["." + tunnels.wbase] : [];
  },
  pushCerts: async ({ force } = {}) => {
    if (tunnels.edge.cur) await relayLink.pushCert({ ...tunnels.edge.cur, force }).catch((e) => log("relay doctor: certificate:", e.message));
    await burrow.domains.pushAll();
  },
  tunnels: () => [...tunnels.tunnels.values()].filter((t) => t.enabled && t.kind !== "site" && t.kind !== "clone")
    .map((t) => ({ port: t.port, name: t.name || t.sub || null, host: tunnels.hostFor(t.port), targetHost: t.targetHost, targetPort: t.targetPort })),
  // the VPS in Machines (2.28 links it in as root): what fixes it when the link can't
  root: () => {
    const id = relayLink.machine()?.id, m = id && fleet.list().find((x) => x.id === id);
    return m ? { run: (script) => fleet.ssh(m, script, { timeout: 60000 }) } : null;
  },
  updateAgent: () => relayUp(),
  notify: (n) => notify("relay", n),
  resolved: (key) => {
    let changed = false;
    for (const x of noticesLoad()) if (x.source === "relay" && x.key === key && !x.read) { x.read = true; changed = true; }
    if (changed) noticesSave();
  },
});
relayDoctor.start();
setTimeout(() => { if (relayWanted()) relayDoctor.run({ reason: "start" }).catch(() => {}); }, 120e3).unref();
async function relayRoute(method, path, readJson) {
  const ok = (json) => ({ status: 200, json });
  try {
    if (path === "/relay" && method === "GET") return ok({ ...relayLink.view(), wanted: relayWanted(), naming: { mode: tunnels.naming.mode, certs: tunnels.naming.certs, relay: tunnels.naming.relay, route: tunnels.naming.route } });
    if (path === "/relay/setup" && method === "POST") {
      if (!tunnels.domain) return { status: 409, json: { error: "Link a domain first: the relay carries its tunnel names." } };
      const b = await readJson();
      // the names the agent answers for: the wildcard in use, or the one about to be (the prefix being set up)
      const prefix = b.prefix !== undefined ? cleanNaming({ mode: "wildcard", prefix: b.prefix, certs: "self" }).prefix : tunnels.wildcard ? tunnels.naming.prefix : "tunnel";
      const r = relayLink.setup({ host: b.host || tunnels.naming.relay, port: b.port, suffix: "." + (prefix ? `${prefix}.${tunnels.parent}` : tunnels.parent) });
      const base = `https://${mainHost()}`;
      return ok({ ...r, command: `curl -fsSL '${base}/__gate/relay/agent.sh?t=${r.token}' | sudo bash` });
    }
    if (path === "/relay/check" && method === "POST") { await verifyRelay(); return ok({ ...relayLink.view(), wanted: relayWanted() }); }
    if (path === "/relay/forget" && method === "POST") {
      if (tunnels.wildcard && tunnels.naming.certs === "self" && tunnels.naming.route === "vps") return { status: 409, json: { error: "The tunnels go through this VPS: move them elsewhere first (Settings → Domain)." } };
      relayLink.forget(); superviseRelay(); return ok(relayLink.view());
    }
    if (path === "/relay/push" && method === "POST") return ok(await relayLink.pushCert({ ...tunnels.edge.cur, force: true }) || {});
    // the doctor: its last report, or a run now ({fix: false} only looks)
    if (path === "/relay/doctor" && method === "GET") return ok(relayDoctor.view());
    if (path === "/relay/doctor" && method === "POST") { const b = await readJson().catch(() => ({})); return ok({ last: await relayDoctor.run({ fix: b?.fix !== false, reason: "asked" }), running: false }); }
  } catch (e) { return { status: 400, json: { error: e.message } }; }
  return null;
}
const prevOnCert = edgeListen;
tunnels.edge.onCert = () => { prevOnCert(); if (relayLink.link.state === "up") relayLink.pushCert(tunnels.edge.cur).catch((e) => log("relay: couldn't push the renewed certificate:", e.message)); };
// this machine stopped holding the certificate: nothing listens for it any more
tunnels.edge.onStop = () => {
  if (!edgeServer) return;
  const srv = edgeServer; edgeServer = null;
  srv.close(); srv.closeAllConnections?.();
  log("edge: stopped (this machine no longer holds the tunnels' certificate)");
};
if (tunnels.selfCerts) edgeListen();

// ---------- the local control socket (Burrow's, see burrow/index.mjs) ----------

// The command line (bin/aegis) does everything the browser does, through this
// socket: it is mode 600, so only this machine's user who runs Aegis gets in,
// the same user who can already read secret.key and data/. That is why the
// login can be created or changed here without the browser's sealing.
const USER_RE = /^[A-Za-z0-9._@-]{2,64}$/;
async function overview() {
  const d = settings.get("domain"), auth = settings.auth(), integ = listIntegrations();
  const forge = integ.find((i) => i.kind === "selkies-forge");
  const tx = settings.get("termix");
  const u = updater.view();
  return {
    app: "aegis-burrow", version: VERSION, started: startedAt, pid: process.pid,
    setup: !auth, user: auth?.username || null, setupOpen: !auth && Date.now() - startedAt < SETUP_WINDOW_MS,
    local: LOCAL_URL + "/", mainHost: mainHost(),
    domain: d ? { mainHost: d.mainHost, managed: !!d.managed, label: d.mainHost.split(".")[0], zone: d.zone?.name || d.mainHost.split(".").slice(1).join(".") } : null,
    domains: burrow.domains.list().map((x) => ({ zone: x.zone.name, dashboard: x.label ? `${x.label}.${x.zone.name}` : null, tunnels: x.tunnels })),
    serveo: { ...serveo.state(), wanted: serveoWanted() },
    burrow: burrow.status(),
    termix: tx ? { upstream: tx.upstream, container: tx.container || null } : null,
    forge: forge ? { version: forge.version, url: forge.url, linked: !!forge.addon } : null,
    pack: (({ decided, skipped }) => ({ decided, skipped }))(pack.status()),
    pages: pagesView(),
    update: { current: u.current, latest: u.latest, available: u.available, checked: u.checked, auto: u.auto, error: u.error, entries: (u.entries || []).slice(0, 8) },
  };
}
burrow.listenControl(join(DATA, "control.sock"), async (method, path, readJson) => {
  const ok = (json) => ({ status: 200, json }), no = (status, error) => ({ status, json: { error } });
  // the serveo link (aegis serveo)
  if (path === "/serveo" && method === "GET") return ok(serveo.state());
  if (path === "/serveo" && method === "POST") { setServeo((await readJson()).on !== false); return ok(serveo.state()); }
  // Aegis Relay (setup link, status, forget)
  if (path.startsWith("/relay")) { const r = await relayRoute(method, path, readJson); if (r) return r; }
  // the home screen and `aegis status`
  if (path === "/overview" && method === "GET") return ok(await overview());
  if (path === "/audit" && method === "GET") return ok({ events: auditRead(300) });
  // aegis setup: the first login, from the terminal
  if (path === "/setup" && method === "POST") {
    if (settings.auth()) return no(409, "The login already exists. Change it with: aegis passwd");
    const f = await readJson(), username = String(f.username || "").trim();
    if (!USER_RE.test(username)) return no(400, "Username: 2-64 letters, digits, . _ @ -");
    if (String(f.password || "").length < 10) return no(400, "Use at least 10 characters.");
    setPassword(username, String(f.password));
    log("setup: login created for", username, "from the command line"); audit("login created", null, { from: "command line", user: username });
    return ok({ ok: true, user: username });
  }
  // aegis passwd: a new login; every browser is signed out
  if (path === "/password" && method === "POST") {
    if (!settings.auth()) return no(409, "There is no login yet. Create it with: aegis setup");
    const f = await readJson(), username = String(f.username || settings.auth().username).trim();
    if (!USER_RE.test(username)) return no(400, "Username: 2-64 letters, digits, . _ @ -");
    if (String(f.password || "").length < 10) return no(400, "Use at least 10 characters.");
    setPassword(username, String(f.password));
    log("password changed from the command line - every session is signed out"); audit("password changed", null, { from: "command line", user: username });
    return ok({ ok: true, user: username });
  }
  // the pack
  if (path === "/pack" && method === "GET") { await pack.detect(); return ok(pack.status()); }
  if (path === "/pack" && method === "POST") {
    const b = await readJson();
    if (b.skip) { pack.skip(); return ok(pack.status()); }
    return ok(pack.run(b));
  }
  // the domain
  if (path === "/cf" && method === "GET") return ok(cloudflare.state());
  if (path === "/cf/login" && method === "POST") return ok(await cloudflare.startLogin());
  if (path === "/cf/cancel" && method === "POST") return ok(cloudflare.cancelLogin());
  if (path === "/cf/link" && method === "POST") return ok(await cloudflare.link((await readJson()).label));
  if (path === "/cf/rename" && method === "POST") return ok(await cloudflare.rename((await readJson()).label));
  if (path === "/cf/unlink" && method === "POST") return ok(await cloudflare.unlink());
  // Termix
  if (path === "/termix" && method === "GET") return ok(await termix.status());
  // updates
  if (path === "/update" && method === "GET") return ok(updater.view());
  if (path === "/update/check" && method === "POST") return ok(await updater.check());
  if (path === "/update/versions" && method === "GET") return ok(await updater.versions());
  if (path === "/update/rollback" && method === "POST") {
    const b = await readJson();
    const job = await updater.rollback(b.version, { hold: b.hold !== false });
    return job.state === "error" ? no(400, job.error) : ok({ ...updater.view(), job });
  }
  if (path === "/update/hold" && method === "POST") { updater.setHold((await readJson()).version || null); return ok(await updater.versions()); }
  if (path === "/update/apply" && method === "POST") { const job = await updater.apply(); return job.state === "error" ? no(500, job.error) : ok({ ...updater.view(), job }); }
  if (path === "/prefs" && method === "POST") { savePrefs(await readJson()); return ok({ ok: true }); }
  // the domain and its DNS records, read-only (addon scripts: Burrow Pages checks them on install)
  if (path === "/dns" && method === "GET") {
    const d = settings.get("domain");
    let records = [], error = null;
    try { records = await tunnels.dnsRecords(); } catch (e) { error = e.message; }
    return ok({ domain: d ? { mainHost: d.mainHost, zone: d.mainHost.split(".").slice(1).join(".") } : null, records, error });
  }
  // addons, from this machine (aegis addons …): what's installed, what has an update, and
  // install / update / uninstall / an action, followed as a job. The dashboard's Addons tab, without a browser.
  if (path === "/addons" && method === "GET") return ok({ addons: await addons.list() });
  if (path === "/addons/updates" && method === "GET") return ok({ updates: addons.updates() });
  if (path === "/addons/check" && method === "POST") { await addons.checkAll(0); return ok({ updates: addons.updates() }); }
  if (path === "/addons/add" && method === "POST") { const src = ((await readJson()) || {}).source; audit("addon: added from the command line", null, { source: String(src || "").slice(0, 200) }); return ok({ addon: await addons.add(src) }); }
  const aj = /^\/addons\/jobs\/([0-9a-f]{12})$/.exec(path);
  if (aj && method === "GET") return ok(addons.job(aj[1]).view(0));
  // the askpass helper (bin/aegis-askpass) of a running root job: POST {token} -> the password.
  // Only here, on the socket (mode 600); the dashboard has no such route.
  if (path === "/askpass" || path.startsWith("/askpass/")) return addons.root.route(method, path, readJson);
  const ar = /^\/addons\/([a-z0-9-]{2,40})\/root$/.exec(path);
  if (ar && method === "GET") return ok(await addons.rootInfo(ar[1]));
  // a root job run in the user's own terminal (bin/cli.mjs addon-here, burrow/terminal.mjs):
  // its script step, once, then its lines and its exit code, with the job's token. Only here, on the socket.
  const ats = /^\/addons\/([a-z0-9-]{2,40})\/runspec$/.exec(path);
  const atl = /^\/addons\/jobs\/([0-9a-f]{12})\/(line|done)$/.exec(path);
  if ((ats || atl) && method === "POST") {
    const b = (await readJson()) || {};
    try {
      if (ats) {
        audit(`addon: ${b.op}${b.op === "action" ? ` ${b.action}` : ""} run in a terminal (as root)`, null, { addon: ats[1] });
        return ok(await addons.terminalRun(ats[1], b));
      }
      return ok(atl[2] === "line" ? addons.terminalLines(atl[1], b) : addons.terminalDone(atl[1], b));
    } catch (e) { return { status: e.status || 400, json: { error: e.message } }; }
  }
  const av = /^\/addons\/([a-z0-9-]{2,40})\/versions$/.exec(path);
  if (av && method === "GET") { try { return ok(addons.versionsView(av[1])); } catch (e) { return { status: e.status || 400, json: { error: e.message } }; } }
  const ao = /^\/addons\/([a-z0-9-]{2,40})\/(install|update|uninstall|rollback|action|check|autorestart)$/.exec(path);
  if (ao && method === "POST") {
    const [, id, op] = ao, b = (await readJson()) || {};
    if (["install", "update", "uninstall", "action", "rollback"].includes(op)) {
      let grant;
      try { grant = await addons.rootGrant(id, op, { password: b.password, action: b.action }); }
      catch (e) { if (e instanceof RootError) return { status: e.status, json: { error: e.message, ...e.extra } }; throw e; }
      audit(`addon: ${op}${op === "action" ? ` ${b.action}` : ""}${grant ? " as administrator (root)" : ""} from the command line`, null, { addon: id });
      return ok({ job: addons.runOp(op, id, b, grant) });
    }
    audit(`addon: ${op} from the command line`, null, { addon: id });
    if (op === "check") return ok(await addons.checkUpdates(id));
    if (op === "autorestart") return ok(addons.setAutoRestart(id, b.on !== false));
  }
  const xc = /^\/x\/([a-z0-9][a-z0-9-]{1,39})(\/[^?]*)?$/.exec(path);
  if (xc) return extRoute(xc[1], xc[2] || "/", method, new URLSearchParams(), readJson, "control");
  return null;
});
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { relayLink.stop(); burrow.stop(); serveo.stop(); devices.stop(); process.exit(0); });

const LOCAL_URL = `${TLS ? "https" : "http"}://${LISTEN.host === "0.0.0.0" || LISTEN.host === "::" ? "127.0.0.1" : LISTEN.host}:${LISTEN.port}`;
// data/runtime.json: where it answers right now (bin/aegis prints these)
let lastRuntime = "";
function writeRuntime() {
  const r = { pid: process.pid, url: LOCAL_URL + "/", started: startedAt, version: VERSION, mainHost: mainHost(), serveo: serveo.url ? serveo.url + "/" : null };
  const j = JSON.stringify(r);
  if (j === lastRuntime) return;
  lastRuntime = j;
  try { writeJson(join(DATA, "runtime.json"), r, 0o644); } catch { /* read-only data dir: fine */ }
}
const startedAt = Date.now();
setInterval(writeRuntime, 2000).unref();

server.listen(LISTEN.port, LISTEN.host, () => {
  const local = LOCAL_URL;
  log(`aegis × burrow ${VERSION} on ${local}${mainHost() ? ` (dashboard https://${mainHost()})` : ""}, tunnels: ${tunnels.mode}`);
  writeRuntime();
  updater.confirmBoot();
  if (serveoWanted()) startServeo();
  if (!settings.auth()) {
    const t = settings.setupToken();
    log(`first run: create the login at ${local}/__gate/setup${t ? `?t=${t}` : ""}`);
  }
});
