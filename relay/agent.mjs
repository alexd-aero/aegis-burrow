// Aegis Relay agent: the small program on your VPS that carries your tunnels
// to your Aegis at home, and nothing else.
//
//   visitors ──TLS──▶ this VPS (Caddy, or the agent itself on :443)
//            ──▶ agent ──signed request──▶ 127.0.0.1:UPSTREAM  (a reverse SSH tunnel
//                                          that only your Aegis can open, as the
//                                          locked-down user aegis-relay)
//            ──▶ your Aegis, which checks the signature before anything else
//
// Every request is signed with a key only this agent and your Aegis hold
// (HMAC-SHA256 over a timestamp, a one-time nonce, the host, the visitor's
// address, the method and the path). Nothing else on this server can feed
// requests to your Aegis, and nothing can claim to be another visitor.
// The certificates (*.<your tunnel zone>, Let's Encrypt, renewed by your Aegis)
// come over the same tunnel, signed the same way: the first zone's from the
// install, and one per domain your Aegis adds later (POST /cert with its suffix;
// the list is kept in zones.json next to the config). Only names one level under
// those zones are served; everything else gets 421. Your Aegis can also send a
// newer agent (POST /update, signed): it is checked with `node --check`, takes
// this file's place, and systemd starts it again. And it can link this server
// into your Aegis's Machines (POST /fleet/link, signed): the same link script
// any machine runs, run here as root, so a VPS added for the tunnels is a
// machine like any other without a second command (agent 1.4+). Neither gives
// your Aegis more than /update already did.
//
// Public tunnels are checked here first (POST /edge from your Aegis: which names
// are public, which addresses a scan cleared or are yours, which are banned):
// someone new gets a "checking your connection" page from this server while a
// signed one-line "scan this address" goes home, and their request reaches your
// Aegis only once the scan cleared them. Banned addresses are turned away here
// too. A request with a device key is passed on: only your Aegis can tell a
// real one, and it does.
//
// Clock (agent 1.6+): signatures only hold for a minute, so a clock that
// drifted makes everything look unsigned. This agent says its time even when it
// refuses a request (so your Aegis can sign in its time and keep working), and
// POST /clock (signed) switches NTP on here, and failing that sets the clock
// from the time your Aegis read off the web.
//
// Standby (agent 1.5+): your Aegis can hand this agent a stand-in for a tunnel
// (a copy of a folder, or a message page), kept in /etc/aegis-relay/standby/<host>/.
// While your Aegis answers, nothing changes. When it doesn't (the link is down,
// it says 502/503/504, or it says nothing for 8 seconds), visitors of that
// tunnel get the stand-in instead, marked X-Aegis-Standby: 1, behind the same
// lock as the tunnel: public, or a small password form checked against a copy
// of the tunnel's password hash (scrypt; never the password itself). Files come
// over the signed control channel one by one, each bound to its signature by
// its sha256, and a commit swaps the new copy in at once.
//
// One file, no dependencies, Node 18+. Config: /etc/aegis-relay/config.json.
// Installed by the one-line command your Aegis shows (Settings → Domain).

import { createServer as httpServer, request as httpRequest } from "node:http";
import { createServer as httpsServer } from "node:https";
import { createSecureContext } from "node:tls";
import { createHash, createHmac, randomBytes, scrypt, timingSafeEqual, X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, chmodSync, chownSync, statSync, rmSync, readdirSync, copyFileSync,
         createReadStream, createWriteStream } from "node:fs";
import { execFile, execFileSync } from "node:child_process";
import { join, dirname, sep, extname } from "node:path";

export const VERSION = "1.6.0";
export const FEATURES = ["zones", "update", "edge", "fleet", "standby", "clock"];
export const STANDBY_LIMITS = { files: 2000, bytes: 50 * 1024 * 1024 };
const SUFFIX_RE = /^(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,63}$/;
const CONFIG = process.env.AEGIS_RELAY_CONFIG || "/etc/aegis-relay/config.json";

// ------------------------------------------------------------------ the signature (same as Aegis's relaylink.mjs)
export function sign(key, { host, ip, method, url, ts = Date.now(), nonce = randomBytes(12).toString("base64url") }) {
  const mac = createHmac("sha256", key).update(`v1\n${ts}\n${nonce}\n${host}\n${ip}\n${method}\n${url}`).digest("base64url");
  return `v1.${ts}.${nonce}.${mac}`;
}
const seen = new Map();
export function verify(key, header, { host, ip, method, url }, now = Date.now()) {
  const m = /^v1\.(\d{10,16})\.([A-Za-z0-9_-]{8,40})\.([A-Za-z0-9_-]{43})$/.exec(String(header || ""));
  if (!m) return false;
  const ts = Number(m[1]);
  if (Math.abs(now - ts) > 60e3) return false;
  const want = createHmac("sha256", key).update(`v1\n${ts}\n${m[2]}\n${host}\n${ip}\n${method}\n${url}`).digest();
  const got = Buffer.from(m[3], "base64url");
  if (got.length !== want.length || !timingSafeEqual(got, want)) return false;
  if (seen.has(m[2])) return false;                                  // replayed
  seen.set(m[2], ts);
  if (seen.size > 20000) for (const [n, t] of seen) { if (now - t > 120e3) seen.delete(n); if (seen.size < 10000) break; }
  return true;
}

// ------------------------------------------------------------------ the pages a visitor may get instead
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
// kind "checking" (a scan is on its way; it reloads by itself) or "blocked"
export function visitorPage(kind, { ip = "", retry = 2 } = {}) {
  const checking = kind === "checking";
  const title = checking ? "Checking your connection" : "Access blocked";
  const text = checking
    ? "This site checks every new visitor's address before letting it through. Yours is being checked right now; this page reloads by itself in a moment."
    : "This site's protection blocked your address. If you think that's a mistake, tell the site's owner the address and time below.";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${checking ? `<meta http-equiv="refresh" content="${Number(retry) || 2}">` : ""}<meta name="robots" content="noindex"><title>${title}</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#030304;color:#e8eaed;font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px;box-sizing:border-box}
.c{max-width:420px;width:100%;padding:28px 28px 22px;border:1px solid rgba(255,255,255,.1);border-radius:18px;background:#0f1012;box-sizing:border-box}
.i{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;margin-bottom:16px;border:1px solid ${checking ? "rgba(122,167,255,.35);background:rgba(122,167,255,.08);color:#7aa7ff" : "rgba(255,90,82,.35);background:rgba(255,90,82,.08);color:#ff5a52"}}
.i svg{width:22px;height:22px}${checking ? ".i svg{animation:s 1.1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}" : ""}
h1{font-size:18px;margin:0 0 6px;letter-spacing:-.01em}p{margin:0;color:#8a8f97}dl{margin:18px 0 0;padding-top:14px;border-top:1px solid rgba(255,255,255,.08);display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font:12px ui-monospace,Menlo,Consolas,monospace;color:#8a8f97}dt{color:#555a62}dd{margin:0;overflow-wrap:anywhere}</style></head>
<body><main class="c"><div class="i">${checking ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.56"/></svg>' : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>'}</div>
<h1>${title}</h1><p>${text}</p><dl><dt>Address</dt><dd>${esc(ip)}</dd><dt>Time</dt><dd>${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</dd></dl></main></body></html>`;
}

// ------------------------------------------------------------------ standby (1.5+)
const SHA_RE = /^[0-9a-f]{64}$/;
const B64_RE = /^[A-Za-z0-9_-]{4,200}$/;
export const STANDBY_HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
// A file's place in a stand-in: relative, "/"-separated, no empty, ".", ".." or
// hidden parts. -> the path, or null
export function standbyPath(p) {
  if (typeof p !== "string" || !p || p.length > 512 || /[\0\\]/.test(p)) return null;
  const parts = p.split("/");
  if (parts.length > 24 || parts.some((x) => !x || x === "." || x === ".." || x.startsWith("."))) return null;
  return p;
}
// Every token and cookie of the standby is an HMAC with the relay key, under a
// label of its own (never the shape of a request signature).
export const standbyMac = (key, ...parts) => createHmac("sha256", key).update(["aegis-standby", ...parts].join("\n")).digest("base64url");
// The gate's "Preview the fallback" link: https://<host>/?__aegis_standby=<token>
export function previewToken(key, host, ttl = 10 * 60e3, now = Date.now()) {
  const exp = now + Math.min(ttl, 10 * 60e3);
  return `p1.${exp}.${standbyMac(key, "preview", String(host).toLowerCase(), exp)}`;
}
const macOk = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const MIME = { ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8", ".json": "application/json", ".map": "application/json", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
  ".xml": "application/xml", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
  ".avif": "image/avif", ".ico": "image/x-icon", ".bmp": "image/bmp", ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf", ".otf": "font/otf",
  ".mp4": "video/mp4", ".webm": "video/webm", ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".wav": "audio/wav", ".pdf": "application/pdf",
  ".wasm": "application/wasm", ".webmanifest": "application/manifest+json", ".csv": "text/csv; charset=utf-8" };
export const mimeOf = (p) => MIME[extname(p).toLowerCase()] || "application/octet-stream";
const STANDBY_CSS = `:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--line:rgba(0,0,0,.1);--text:#16181d;--muted:#5b616b;--accent:#2f6fe0}
@media (prefers-color-scheme:dark){:root{--bg:#0b0c0e;--card:#141518;--line:rgba(255,255,255,.1);--text:#e8eaed;--muted:#9aa0a8;--accent:#7aa7ff}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px;box-sizing:border-box}
main{max-width:520px;width:100%;padding:32px 30px 26px;border:1px solid var(--line);border-radius:18px;background:var(--card);box-sizing:border-box}
h1{font-size:22px;line-height:1.3;margin:0 0 10px;letter-spacing:-.01em}p{margin:0 0 12px;color:var(--muted);white-space:pre-line;overflow-wrap:anywhere}
small{display:block;margin-top:18px;color:var(--muted);font-size:12.5px}`;
// kind "page": the owner's words, and back home by itself every 30 seconds
export function standbyPage({ title, message } = {}) {
  const t = esc(title || "Back soon");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><meta name="robots" content="noindex"><title>${t}</title><style>${STANDBY_CSS}</style></head>
<body><main><h1>${t}</h1><p>${esc(message || "This site is taking a short break. This page checks again by itself every 30 seconds.")}</p><small>This page reloads by itself every 30 seconds.</small></main></body></html>`;
}
export function unlockPage({ error = "", next = "/" } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Password</title><style>${STANDBY_CSS}
form{display:grid;gap:10px;margin-top:6px}input{font:inherit;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:transparent;color:var(--text)}
button{font:inherit;font-weight:600;padding:10px 12px;border-radius:10px;border:0;background:var(--accent);color:#fff;cursor:pointer}.e{color:#e5484d;font-size:14px;min-height:1.2em;margin:0}</style></head>
<body><main><h1>This site has a password</h1><p>Type it to go on.</p><form method="post" action="/__aegis_standby/unlock"><input type="hidden" name="next" value="${esc(next)}">
<input type="password" name="password" autocomplete="current-password" autofocus required aria-label="Password"><p class="e" role="alert">${esc(error)}</p><button>Open</button></form></main></body></html>`;
}

// ------------------------------------------------------------------ the agent
export function startAgent(cfg, { log = (...a) => console.log(new Date().toISOString(), ...a) } = {}) {
  const key = Buffer.from(cfg.key, "base64url");
  const suffix = String(cfg.suffix).toLowerCase();                    // ".tunnel.example.com": the first zone, from the install
  const stats = { requests: 0, ws: 0, refused: 0, upstreamErrors: 0, edgeChecks: 0, edgeBlocked: 0, standby: 0, since: Date.now(), lastOk: 0 };
  const certFile = join(cfg.certDir, "tunnel.crt"), keyFile = join(cfg.certDir, "tunnel.key");
  // every zone: the first one, and the ones your Aegis added since (zones.json)
  const zonesFile = cfg.zonesFile || join(dirname(cfg.certDir), "zones.json");
  let extra = [];
  try { extra = JSON.parse(readFileSync(zonesFile, "utf8")).filter((z) => SUFFIX_RE.test(z) && z !== suffix); } catch { /* none yet */ }
  const zones = () => [suffix, ...extra];
  const filesOf = (z) => z === suffix ? { crt: certFile, key: keyFile } : { crt: join(cfg.certDir, `z${z}.crt`), key: join(cfg.certDir, `z${z}.key`) };
  const saveZones = () => { mkdirSync(dirname(zonesFile), { recursive: true }); writeFileSync(zonesFile + ".tmp", JSON.stringify(extra)); renameSync(zonesFile + ".tmp", zonesFile); };
  const zoneOf = (host) => {
    host = String(host || "").toLowerCase().replace(/:\d+$/, "");
    let best = null;
    for (const z of zones()) if (host.endsWith(z) && host.length > z.length && !host.slice(0, -z.length).includes(".") && (!best || z.length > best.length)) best = z;
    return best;
  };
  const ours = (host) => (zoneOf(host) ? String(host).toLowerCase().replace(/:\d+$/, "") : null);

  // the visitor's address: Caddy in front says it in x-aegis-client (only believed from this machine)
  const visitor = (req) => {
    const peer = String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
    if (cfg.mode === "caddy") return /^(127\.|::1$)/.test(peer) ? String(req.headers["x-aegis-client"] || "").split(",")[0].trim() || null : null;
    return peer;
  };
  const upstreamHeaders = (req, host, ip) => {
    const h = {};
    for (const [k, v] of Object.entries(req.headers)) if (!/^(x-aegis-|cf-connecting-ip$|x-forwarded-|x-real-ip$|true-client-ip$|forwarded$)/i.test(k)) h[k] = v;
    h.host = host;
    h["x-aegis-relay-ip"] = ip;
    h["x-aegis-relay"] = sign(key, { host, ip, method: req.method, url: req.url });
    return h;
  };
  // public tunnels, checked here first (POST /edge)
  let edge = { on: false, epoch: null, hosts: new Set(), cleared: new Set(), banned: new Set() };
  const pinged = new Map();                                            // ip -> when home was asked to scan it
  const DEVICE_RE = /(?:^|;\s*)(?:__Host-)?aegis-dev=/;
  const scanPing = (ip) => {
    const last = pinged.get(ip) || 0;
    if (Date.now() - last < 5000) return;
    pinged.set(ip, Date.now());
    if (pinged.size > 20000) for (const [k, t] of pinged) { if (Date.now() - t > 60e3) pinged.delete(k); if (pinged.size < 10000) break; }
    const url = "/__aegis-relay/scan";
    const r = httpRequest({ host: "127.0.0.1", port: cfg.upstreamPort, method: "POST", path: url, timeout: 10000,
      headers: { host: "scan", "x-aegis-relay-ip": ip, "x-aegis-relay": sign(key, { host: "scan", ip, method: "POST", url }), "content-length": 0 } }, (res) => res.resume());
    r.on("timeout", () => r.destroy()); r.on("error", () => {});
    r.end();
  };
  // -> null (on to your Aegis) or "checking" / "blocked"
  const edgeStop = (req, host, ip) => {
    if (DEVICE_RE.test(String(req.headers.cookie || ""))) return null;       // a device key: your Aegis checks it
    if (edge.banned.has(ip)) { stats.edgeBlocked++; return "blocked"; }
    if (edge.on && edge.hosts.has(host) && !edge.cleared.has(ip)) { stats.edgeChecks++; scanPing(ip); return "checking"; }
    return null;
  };
  const turnAway = (res, kind, ip) => {
    res.writeHead(403, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...(kind === "checking" ? { "Retry-After": "2" } : {}) });
    res.end(visitorPage(kind, { ip }));
  };
  const offline = (res) => {
    res.writeHead(502, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Aegis-Relay": "home-offline" });
    res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Not connected</title><body style="margin:0;display:grid;place-items:center;min-height:100vh;background:#0b0c0e;color:#e8eaed;font:15px system-ui,sans-serif"><div style="max-width:380px;padding:24px"><h1 style="font-size:18px">The home end isn\'t connected</h1><p style="color:#8a8f97">This relay is up, but the Aegis it carries isn\'t connected to it right now. Try again in a minute.</p></div>');
  };

  // ---------------- standby: the stand-ins, on disk and in memory
  const sbDir = cfg.standbyDir || join(dirname(cfg.certDir), "standby");
  const STANDBY_WAIT = Number(cfg.standbyWait) || 8000;               // how long home gets to start answering
  const sites = new Map();                                             // primary host -> site
  const aliases = new Map();                                           // every host it answers for -> site
  const staged = new Map();                                            // host -> bytes staged
  const index = () => { aliases.clear(); for (const s of sites.values()) for (const h of s.hosts) aliases.set(h, s); };
  const siteOf = (dir, host) => {
    const j = JSON.parse(readFileSync(join(dir, "site.json"), "utf8"));
    const files = new Map(Object.entries(j.files || {}));
    return { ...j, host, root: join(dir, "files"), files, bytes: [...files.values()].reduce((a, f) => a + f.size, 0) };
  };
  try {
    for (const h of readdirSync(sbDir)) if (STANDBY_HOST_RE.test(h)) { try { sites.set(h, siteOf(join(sbDir, h), h)); } catch (e) { log(`standby ${h}:`, e.message); } }
    index();
  } catch { /* none yet */ }
  const sbHeaders = { "X-Aegis-Standby": "1", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin" };
  const cookieOf = (req, name) => {
    const out = [];
    for (const part of String(req.headers.cookie || "").split(/;\s*/)) { const i = part.indexOf("="); if (i > 0 && part.slice(0, i) === name) out.push(part.slice(i + 1)); }
    return out;
  };
  const cookieValid = (req, name, ...parts) => cookieOf(req, name).some((v) => {
    const m = /^(\d{10,16})\.([A-Za-z0-9_-]{43})$/.exec(v);
    return !!m && Number(m[1]) > Date.now() && macOk(m[2], standbyMac(key, ...parts, m[1]));
  });
  const unlocked = (req, sb, host) => sb.access === "public" || (!!sb.lock && cookieValid(req, "__Host-aegis-sb", "unlock", host, sb.lock.epoch));
  const previewing = (req, host) => cookieValid(req, "__Host-aegis-sbp", "preview-cookie", host);
  const fails = new Map();                                             // ip -> recent wrong passwords
  const sbSend = (req, res, status, body, type, extra = {}) => {
    res.writeHead(status, { "Content-Type": type, ...sbHeaders, ...extra });
    res.end(req.method === "HEAD" ? undefined : body);
  };
  // the stand-in itself: GET/HEAD only, behind the tunnel's lock
  function serveStandby(req, res, sb, host) {
    stats.standby++;
    if (req.method !== "GET" && req.method !== "HEAD") return sbSend(req, res, 503, "This site is offline right now; only reading works until it's back.\n", "text/plain; charset=utf-8", { "Retry-After": "30" });
    let u;
    try { u = new URL(req.url, "http://x"); } catch { return sbSend(req, res, 400, "Bad request\n", "text/plain"); }
    if (!unlocked(req, sb, host)) return sbSend(req, res, 401, unlockPage({ next: u.pathname + u.search }), "text/html; charset=utf-8");
    if (sb.kind === "page") return sbSend(req, res, 503, standbyPage(sb), "text/html; charset=utf-8", { "Retry-After": "30" });
    let p;
    try { p = decodeURIComponent(u.pathname).replace(/^\/+/, ""); } catch { return sbSend(req, res, 400, "Bad request\n", "text/plain"); }
    const has = (x) => standbyPath(x) && sb.files.has(x);
    let file = null;
    if (p && has(p)) file = p;
    else if (has((p && !p.endsWith("/") ? p + "/" : p) + "index.html")) {
      if (p && !p.endsWith("/")) { res.writeHead(302, { Location: "/" + encodeURI(p) + "/" + u.search, ...sbHeaders }); return res.end(); }
      file = p + "index.html";
    } else if (has("index.html")) file = "index.html";                // a single-page app's own router
    if (!file) return sbSend(req, res, 404, "Not found\n", "text/plain; charset=utf-8");
    const full = join(sb.root, ...file.split("/"));
    if (!full.startsWith(sb.root + sep)) return sbSend(req, res, 404, "Not found\n", "text/plain; charset=utf-8");
    res.writeHead(200, { "Content-Type": mimeOf(file), "Content-Length": sb.files.get(file).size, ...sbHeaders });
    if (req.method === "HEAD") return res.end();
    createReadStream(full).on("error", () => res.destroy()).pipe(res);
  }
  // the password form's answer: POST /__aegis_standby/unlock (password, next)
  function standbyUnlock(req, res, sb, host, ip) {
    let b = "";
    req.on("data", (d) => { b += d; if (b.length > 4096) req.destroy(); });
    req.on("end", () => {
      const f = new URLSearchParams(b), next0 = String(f.get("next") || "/");
      const next = next0.startsWith("/") && !next0.startsWith("//") && !next0.startsWith("/\\") ? next0 : "/";
      const now = Date.now(), recent = (fails.get(ip) || []).filter((t) => now - t < 15 * 60e3);
      if (recent.length >= 10) return sbSend(req, res, 429, unlockPage({ next, error: "Too many tries. Wait a few minutes." }), "text/html; charset=utf-8", { "Retry-After": "300" });
      const pw = String(f.get("password") || "");
      if (sb.access === "public" || !sb.lock) { res.writeHead(303, { Location: next, ...sbHeaders }); return res.end(); }
      const sc = sb.scrypt || {}, N = Number(sc.N) || 2 ** 15, r = Number(sc.r) || 8, pp = Number(sc.p) || 1;
      const salt = Buffer.from(sb.lock.salt, "base64url"), want = Buffer.from(sb.lock.hash, "base64url");
      if (!pw || pw.length > 256) return wrong();
      scrypt(pw, salt, want.length, { N, r, p: pp, maxmem: 128 * N * r * 2 }, (err, got) => {
        if (err || !timingSafeEqual(got, want)) return wrong();
        fails.delete(ip);
        const exp = Date.now() + 30 * 86400e3;
        res.writeHead(303, { Location: next, "Set-Cookie": `__Host-aegis-sb=${exp}.${standbyMac(key, "unlock", host, sb.lock.epoch, exp)}; Path=/; Max-Age=${30 * 86400}; Secure; HttpOnly; SameSite=Lax`, ...sbHeaders });
        res.end();
      });
      function wrong() {
        recent.push(now); fails.set(ip, recent);
        if (fails.size > 20000) for (const [k, v] of fails) { if (now - v[v.length - 1] > 15 * 60e3) fails.delete(k); if (fails.size < 10000) break; }
        sbSend(req, res, 401, unlockPage({ next, error: "That's not it." }), "text/html; charset=utf-8");
      }
    });
  }

  function onRequest(req, res) {
    const host = ours(req.headers.host), ip = visitor(req);
    if (!host || !ip) { stats.refused++; res.writeHead(421, { "Content-Type": "text/plain" }); return res.end("Misdirected request"); }
    const stop = edgeStop(req, host, ip);
    if (stop) return turnAway(res, stop, ip);
    const sb = aliases.get(host) || null;
    if (sb) {
      if (req.url.startsWith("/__aegis_standby/")) {
        if (req.url === "/__aegis_standby/unlock" && req.method === "POST") return standbyUnlock(req, res, sb, host, ip);
        return sbSend(req, res, 404, "Not found\n", "text/plain");
      }
      // "Preview the fallback": a link the gate made, then a cookie for ten minutes
      const pq = /[?&]__aegis_standby=([^&]*)/.exec(req.url);
      if (pq) {
        const m = /^p1\.(\d{10,16})\.([A-Za-z0-9_-]{43})$/.exec(decodeURIComponent(pq[1]));
        const ok = !!m && Number(m[1]) > Date.now() && Number(m[1]) - Date.now() <= 10 * 60e3 + 5000 && macOk(m[2], standbyMac(key, "preview", host, m[1]));
        if (!ok) return sbSend(req, res, 403, "That preview link has expired. Make a new one in Aegis.\n", "text/plain; charset=utf-8");
        const u = new URL(req.url, "http://x");
        u.searchParams.delete("__aegis_standby");
        const exp = Date.now() + 10 * 60e3;
        res.writeHead(303, { Location: u.pathname + (u.search || ""), "Set-Cookie": `__Host-aegis-sbp=${exp}.${standbyMac(key, "preview-cookie", host, exp)}; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax`, ...sbHeaders });
        return res.end();
      }
      if (previewing(req, host)) return serveStandby(req, res, sb, host);
    }
    stats.requests++;
    let settled = false, piping = false;
    const standIn = () => { if (settled || res.headersSent) return; settled = true; serveStandby(req, res, sb, host); };
    const up = httpRequest({ host: "127.0.0.1", port: cfg.upstreamPort, method: req.method, path: req.url, headers: upstreamHeaders(req, host, ip), timeout: 120000 }, (upRes) => {
      clearTimeout(wait);
      // home answers, but only to say it can't: the stand-in, before anything is written
      if (sb && [502, 503, 504].includes(upRes.statusCode)) { upRes.resume(); return standIn(); }
      settled = true; piping = true;
      stats.lastOk = Date.now();
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    // with a stand-in, home gets STANDBY_WAIT to start answering (not 120 s)
    const wait = sb ? setTimeout(() => { up.destroy(new Error("timeout")); standIn(); }, STANDBY_WAIT) : null;
    up.on("timeout", () => up.destroy(new Error("timeout")));
    up.on("error", () => {
      clearTimeout(wait);
      if (settled) { if (piping && !res.writableEnded) res.destroy(); return; }       // the stand-in's own response is left alone
      stats.upstreamErrors++;
      if (sb) return standIn();
      settled = true;
      if (!res.headersSent) offline(res); else res.destroy();
    });
    req.pipe(up);
  }
  function onUpgrade(req, socket, head) {
    const host = ours(req.headers.host), ip = visitor(req);
    if (!host || !ip) { stats.refused++; return socket.end("HTTP/1.1 421 Misdirected Request\r\n\r\n"); }
    if (edgeStop(req, host, ip)) return socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    stats.ws++;
    const up = httpRequest({ host: "127.0.0.1", port: cfg.upstreamPort, method: req.method, path: req.url, headers: upstreamHeaders(req, host, ip) });
    up.on("upgrade", (upRes, upSock, upHead) => {
      const lines = [`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}`];
      for (let i = 0; i < upRes.rawHeaders.length; i += 2) lines.push(`${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}`);
      socket.write(lines.join("\r\n") + "\r\n\r\n");
      if (upHead?.length) socket.write(upHead);
      if (head?.length) upSock.write(head);
      upSock.pipe(socket).pipe(upSock);
      socket.on("error", () => upSock.destroy()); upSock.on("error", () => socket.destroy());
    });
    up.on("response", (upRes) => { socket.end(`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n\r\n`); });
    up.on("error", () => { stats.upstreamErrors++; socket.destroy(); });
    up.end();
  }

  // the visitors' side: behind Caddy (plain HTTP on loopback), or TLS on :443 itself
  const ctxs = new Map();               // zone -> TLS context
  const loadCtx = () => {
    ctxs.clear();
    for (const z of zones()) {
      const f = filesOf(z);
      try { if (existsSync(f.crt)) ctxs.set(z, createSecureContext({ cert: readFileSync(f.crt), key: readFileSync(f.key), minVersion: "TLSv1.2" })); } catch (e) { log(`certificate for *${z}:`, e.message); }
    }
  };
  loadCtx();
  const front = cfg.mode === "tls"
    ? httpsServer({ SNICallback: (name, cb) => { const c = ctxs.get(zoneOf(name)); c ? cb(null, c) : cb(new Error("not ours")); }, minVersion: "TLSv1.2" }, onRequest)
    : httpServer(onRequest);
  front.on("upgrade", onUpgrade);
  front.on("tlsClientError", () => {});
  front.keepAliveTimeout = 65000;
  front.listen(cfg.mode === "tls" ? cfg.tlsPort || 443 : cfg.httpPort, cfg.mode === "tls" ? "0.0.0.0" : "127.0.0.1",
               () => log(`aegis relay agent ${VERSION}: ${cfg.mode === "tls" ? "TLS on :" + (cfg.tlsPort || 443) : "behind Caddy on 127.0.0.1:" + cfg.httpPort} -> 127.0.0.1:${cfg.upstreamPort}, names ${zones().map((z) => "*" + z).join(" ")}`));

  // the certificate, as Caddy wants it (files + a site), or for the agent's own TLS
  // one site block per zone that has its certificate. TLS 1.3 only, post-quantum key
  // exchange first. HTTP/2 only: Caddy offers HTTP/3 (QUIC, over UDP) to every site,
  // and through the relay it crawled where UDP is throttled (a 3.8 MB file took 23 s,
  // ~1 s over HTTP/2), so these names tell browsers to forget it (Alt-Svc: clear).
  function caddySite() {
    const have = zones().filter((z) => z === suffix || existsSync(filesOf(z).crt));
    return `# Aegis Relay: ${have.map((z) => "*" + z).join(", ")} -> the Aegis at home, through the relay agent (written by it; don't edit)
` + have.map((z) => `*${z} {
	tls ${filesOf(z).crt} ${filesOf(z).key} {
		protocols tls1.3
		curves x25519mlkem768 x25519 secp256r1
	}
	header -Server
	header Alt-Svc clear
	reverse_proxy 127.0.0.1:${cfg.httpPort} {
		header_up X-Aegis-Client {remote_host}
	}
}
`).join("\n");
  }
  // Caddy: our site file, imported by the Caddyfile (a glob over its folder, or a line of
  // its own; an older hand-made site's import line becomes ours), checked with
  // `caddy validate` before the reload, and everything put back if it doesn't pass.
  // an agent that updated itself brings its site up to date (once, and only if Caddy takes it)
  if (cfg.mode === "caddy" && cfg.caddySite && existsSync(cfg.caddySite) && readFileSync(cfg.caddySite, "utf8") !== caddySite()) {
    try { caddyInstall(); log("the relay's Caddy site is up to date"); } catch (e) { log(e.message); }
  }
  function caddyInstall() {
    const site = cfg.caddySite, cf = cfg.caddyfile || "/etc/caddy/Caddyfile";
    const undo = [];
    const keep = (f) => { if (existsSync(f)) { const b = readFileSync(f); undo.push(() => writeFileSync(f, b)); } else undo.push(() => { try { renameSync(f, f + ".failed"); } catch { /* gone */ } }); };
    try {
      if (existsSync(cf)) {
        let text = readFileSync(cf, "utf8");
        const before = text;
        if (cfg.replaces) text = text.split("\n").map((l) => (l.trim() === `import ${cfg.replaces}` ? l.replace(cfg.replaces, site) : l)).join("\n");
        const dir = dirname(site), covered = text.includes(site) || new RegExp(`import\\s+${dir.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}/\\*`).test(text);
        if (!covered) text = text.replace(/\n*$/, `\n\nimport ${site}\n`);
        if (text !== before) { keep(cf); writeFileSync(cf, text); }
      }
      if (cfg.replaces && existsSync(cfg.replaces)) {
        const old = cfg.replaces;
        renameSync(old, old + ".before-aegis-relay");
        undo.push(() => renameSync(old + ".before-aegis-relay", old));
        log("moved aside", old);
      }
      if (!existsSync(site) || readFileSync(site, "utf8") !== caddySite()) { keep(site); mkdirSync(dirname(site), { recursive: true }); writeFileSync(site, caddySite()); }
      if (cfg.reload === false) return;
      execFileSync("caddy", ["validate", "--config", cf, "--adapter", "caddyfile"], { stdio: "pipe", timeout: 30000 });
    } catch (e) {
      for (const u of undo.reverse()) { try { u(); } catch { /* best effort */ } }
      const why = String(e.stderr || e.message).split("\n").filter(Boolean).pop();
      log("caddy didn't accept the change, put back as it was:", why);
      throw new Error(`Caddy didn't accept the relay's site (${why}); nothing was changed`);
    }
    execFile("systemctl", ["reload", "caddy"], (e) => log(e ? `caddy reload failed: ${e.message}` : "caddy reloaded with the new certificate"));
  }
  function installCert(cert, privKey, z = suffix) {
    const x = new X509Certificate(cert);
    mkdirSync(cfg.certDir, { recursive: true });
    const f = filesOf(z), added = z !== suffix && !extra.includes(z);
    const old = [f.crt, f.key].map((p) => (existsSync(p) ? readFileSync(p) : null));
    const write = (file, data, mode) => { writeFileSync(file + ".tmp", data, { mode }); renameSync(file + ".tmp", file); chmodSync(file, mode); };
    write(f.crt, cert, 0o644);
    write(f.key, privKey, 0o640);
    if (cfg.caddyGroup !== undefined) { try { chownSync(f.key, 0, cfg.caddyGroup); } catch { /* not root: tests */ } }
    if (added) { extra.push(z); saveZones(); }
    try { if (cfg.mode === "caddy") caddyInstall(); }
    catch (e) {           // Caddy said no: this zone's files as they were
      [f.crt, f.key].forEach((p, i) => { try { old[i] ? writeFileSync(p, old[i]) : rmSync(p, { force: true }); } catch { /* best effort */ } });
      if (added) { extra = extra.filter((x) => x !== z); saveZones(); }
      throw e;
    }
    loadCtx();
    log(`certificate for ${x.subjectAltName} until ${x.validTo}`);
    return { fingerprint: x.fingerprint256, notAfter: Date.parse(x.validTo) };
  }
  function removeZone(z) {
    if (z === suffix) throw new Error("that's the first zone; reinstall to change it");
    if (!extra.includes(z)) return false;
    extra = extra.filter((x) => x !== z); saveZones();
    const f = filesOf(z);
    rmSync(f.crt, { force: true }); rmSync(f.key, { force: true });
    if (cfg.mode === "caddy") caddyInstall();
    loadCtx();
    log(`no longer serving *${z}`);
    return true;
  }
  const certInfo = (z) => { try { const x = new X509Certificate(readFileSync(filesOf(z).crt)); return { fingerprint: x.fingerprint256, notAfter: Date.parse(x.validTo), names: x.subjectAltName }; } catch { return null; } };

  // ---------------- standby: what your Aegis sends (signed; bodies bound by their sha256)
  //   GET    /standby                         -> {sites: [{host, hosts, kind, fp, files, bytes, at}]}
  //   GET    /standby/<host>                  -> {host, kind, fp, files: {path: {sha, size}}} | 404
  //   PUT    /standby/<host>/file?path=&sha=  raw body; refused unless its sha256 is the signed one
  //   POST   /standby/<host>/commit?sha=      {kind, hosts, title, message, access, lock, scrypt, fp, files}: swapped in at once
  //   DELETE /standby/<host>
  const sbView = (s) => ({ host: s.host, hosts: s.hosts, kind: s.kind, fp: s.fp || null, files: s.files.size, bytes: s.bytes, at: s.at || null });
  function standbyControl(req, res, reply, u, host, op) {
    if (!host) {
      if (req.method === "GET" && !op) return reply(200, { sites: [...sites.values()].map(sbView), limits: STANDBY_LIMITS });
      return reply(404, { error: "not found" });
    }
    if (!STANDBY_HOST_RE.test(host) || !ours(host)) return reply(400, { error: "that isn't a name this relay carries" });
    const dir = join(sbDir, host), stage = join(sbDir, `.staging-${host}`);
    if (req.method === "GET" && !op) {
      const s = sites.get(host);
      return s ? reply(200, { ...sbView(s), files: Object.fromEntries(s.files) }) : reply(404, { error: "no standby for that name", files: {} });
    }
    if (req.method === "DELETE" && !op) {
      const had = sites.delete(host);
      rmSync(dir, { recursive: true, force: true }); rmSync(stage, { recursive: true, force: true }); staged.delete(host);
      index();
      if (had) log(`standby for ${host} removed`);
      return reply(200, { ok: true, removed: had });
    }
    if (req.method === "PUT" && op === "/file") {
      const path = standbyPath(u.searchParams.get("path")), sha = String(u.searchParams.get("sha") || "");
      if (!path || !SHA_RE.test(sha)) { req.resume(); return reply(400, { error: "a file needs a clean path and its sha256" }); }
      mkdirSync(stage, { recursive: true, mode: 0o750 });
      const tmp = join(stage, `.up-${randomBytes(6).toString("hex")}`), h = createHash("sha256"), out = createWriteStream(tmp, { mode: 0o640 });
      let size = 0, failed = null;
      const fail = (status, error) => { if (failed) return; failed = error; out.destroy(); rmSync(tmp, { force: true }); req.resume(); reply(status, { error }); };
      req.on("data", (d) => {
        size += d.length;
        if (size > STANDBY_LIMITS.bytes || (staged.get(host) || 0) + size > STANDBY_LIMITS.bytes * 2) return fail(413, "too large");
        h.update(d);
      });
      req.pipe(out);
      out.on("finish", () => {
        if (failed) return;
        if (h.digest("hex") !== sha) { rmSync(tmp, { force: true }); return reply(400, { error: "the body isn't the file that was signed (sha256 differs)" }); }
        renameSync(tmp, join(stage, sha));
        staged.set(host, (staged.get(host) || 0) + size);
        reply(200, { ok: true, path, sha, size });
      });
      out.on("error", (e) => fail(500, e.message));
      req.on("error", () => fail(400, "upload broken off"));
      return;
    }
    if (req.method === "POST" && op === "/commit") {
      const want = String(u.searchParams.get("sha") || "");
      let b = "";
      req.on("data", (d) => { b += d; if (b.length > 2 * 1024 * 1024) req.destroy(); });
      req.on("end", () => {
        try {
          if (!SHA_RE.test(want) || createHash("sha256").update(b).digest("hex") !== want) return reply(400, { error: "the body isn't the one that was signed (sha256 differs)" });
          const j = JSON.parse(b), site = cleanSite(j, host);
          // the new copy, from what was just sent and what the old copy already had
          const next = join(sbDir, `.next-${host}`), old = sites.get(host), have = new Map();
          if (old) for (const [p, f] of old.files) if (!have.has(f.sha)) have.set(f.sha, join(old.root, ...p.split("/")));
          rmSync(next, { recursive: true, force: true });
          mkdirSync(join(next, "files"), { recursive: true, mode: 0o750 });
          const missing = [];
          for (const [p, f] of site.files) {
            const from = existsSync(join(stage, f.sha)) ? join(stage, f.sha) : have.get(f.sha);
            if (!from || !existsSync(from)) { missing.push(p); continue; }
            const to = join(next, "files", ...p.split("/"));
            mkdirSync(dirname(to), { recursive: true, mode: 0o750 });
            copyFileSync(from, to);
            if (statSync(to).size !== f.size) throw new Error(`${p}: the size doesn't match`);
          }
          if (missing.length) { rmSync(next, { recursive: true, force: true }); return reply(409, { error: `missing ${missing.length} file(s)`, missing: missing.slice(0, 50) }); }
          const at = Date.now();
          writeFileSync(join(next, "site.json"), JSON.stringify({ hosts: site.hosts, kind: site.kind, title: site.title, message: site.message, access: site.access,
                                                                   lock: site.lock, scrypt: site.scrypt, fp: site.fp, at, files: Object.fromEntries(site.files) }), { mode: 0o640 });
          const gone = join(sbDir, `.old-${host}`);
          rmSync(gone, { recursive: true, force: true });
          if (existsSync(dir)) renameSync(dir, gone);
          renameSync(next, dir);
          rmSync(gone, { recursive: true, force: true }); rmSync(stage, { recursive: true, force: true }); staged.delete(host);
          sites.set(host, siteOf(dir, host));
          index();
          log(`standby for ${host}: ${site.kind}${site.kind === "folder" ? `, ${site.files.size} files` : ""} (${site.access})`);
          reply(200, { ok: true, ...sbView(sites.get(host)) });
        } catch (e) { reply(400, { error: e.message }); }
      });
      return;
    }
    req.resume();
    reply(404, { error: "not found" });
  }
  function cleanSite(j, host) {
    if (!j || typeof j !== "object") throw new Error("a standby is an object");
    const kind = j.kind === "page" ? "page" : j.kind === "folder" ? "folder" : null;
    if (!kind) throw new Error("kind is folder or page");
    const hosts = [...new Set([host, ...(Array.isArray(j.hosts) ? j.hosts : []).map((x) => String(x).toLowerCase())])];
    if (hosts.length > 8 || hosts.some((x) => !STANDBY_HOST_RE.test(x) || !ours(x))) throw new Error("hosts: names this relay carries, 8 at most");
    const access = ["public", "password", "login"].includes(j.access) ? j.access : null;
    if (!access) throw new Error("access is public, password or login");
    let lock = null;
    if (access !== "public") {
      const l = j.lock || {};
      if (![l.salt, l.hash, l.epoch].every((x) => typeof x === "string" && B64_RE.test(x))) throw new Error("a locked standby needs the password's hash");
      lock = { salt: l.salt, hash: l.hash, epoch: l.epoch };
    }
    const sc = j.scrypt || {}, N = Number(sc.N || 2 ** 15), r = Number(sc.r || 8), p = Number(sc.p || 1);
    if (!(N >= 1024 && N <= 2 ** 17 && (N & (N - 1)) === 0 && r >= 1 && r <= 16 && p >= 1 && p <= 4)) throw new Error("scrypt parameters out of range");
    const files = new Map();
    let bytes = 0;
    if (kind === "folder") {
      const ents = Object.entries(j.files || {});
      if (ents.length > STANDBY_LIMITS.files) throw new Error(`more than ${STANDBY_LIMITS.files} files`);
      for (const [p0, f] of ents) {
        const pth = standbyPath(p0);
        if (!pth || !f || !SHA_RE.test(String(f.sha)) || !Number.isInteger(f.size) || f.size < 0) throw new Error(`bad file entry ${String(p0).slice(0, 80)}`);
        bytes += f.size;
        files.set(pth, { sha: f.sha, size: f.size });
      }
      if (bytes > STANDBY_LIMITS.bytes) throw new Error(`more than ${STANDBY_LIMITS.bytes / 1048576} MB`);
      const paths = new Set(files.keys());
      for (const pth of paths) { const parts = pth.split("/"); for (let i = 1; i < parts.length; i++) if (paths.has(parts.slice(0, i).join("/"))) throw new Error(`${pth}: a file is in the way of a folder`); }
    }
    return { kind, hosts, access, lock, scrypt: { N, r, p }, files, title: String(j.title || "").slice(0, 120), message: String(j.message || "").slice(0, 2000), fp: String(j.fp || "").slice(0, 100) };
  }

  // the control side: only through the tunnel, only signed by your Aegis
  const control = httpServer((req, res) => {
    const reply = (status, obj) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    // the time goes with a refusal too: a clock that drifted is the usual reason for one
    if (!verify(key, req.headers["x-aegis-relay"], { host: "agent", ip: "-", method: req.method, url: req.url })) return reply(401, { error: "not signed by your Aegis", now: Date.now() });
    if (req.method === "GET" && req.url === "/status") {
      return reply(200, { version: VERSION, features: FEATURES, mode: cfg.mode, suffix, now: Date.now(), cert: certInfo(suffix),
                          zones: zones().map((z) => ({ suffix: z, cert: certInfo(z) })), stats,
                          edge: { on: edge.on, epoch: edge.epoch, hosts: edge.hosts.size, cleared: edge.cleared.size, banned: edge.banned.size },
                          standby: { sites: sites.size } });
    }
    const su = new URL(req.url, "http://agent");
    const sm = /^\/standby(?:\/([^/]+))?(\/file|\/commit)?$/.exec(su.pathname);
    if (sm) return standbyControl(req, res, reply, su, sm[1] ? sm[1].toLowerCase() : null, sm[2] || "");
    const body = (max, fn) => {
      let b = "";
      req.on("data", (d) => { b += d; if (b.length > max) req.destroy(); });
      req.on("end", () => { try { fn(JSON.parse(b || "{}")); } catch (e) { reply(400, { error: e.message }); } });
    };
    if (req.method === "POST" && req.url === "/cert") {
      return body(64 * 1024, ({ cert, key: k, suffix: z = suffix }) => {
        z = String(z).toLowerCase();
        if (!SUFFIX_RE.test(z)) return reply(400, { error: "that isn't a zone" });
        const x = new X509Certificate(cert);
        if (!x.subjectAltName.split(", ").some((n) => n === `DNS:*${z}`)) return reply(400, { error: `that certificate isn't for *${z}` });
        reply(200, { ok: true, suffix: z, ...installCert(cert, k, z) });
      });
    }
    // who may pass: in full ({full, epoch, on, hosts, cleared, banned}), or what changed since
    // ({epoch, on?, hosts?, add: {cleared, banned}, del: {cleared, banned}}); 409 when this agent lost the thread
    if (req.method === "POST" && req.url === "/edge") {
      return body(16 * 1024 * 1024, (b) => {
        const list = (x) => (Array.isArray(x) ? x.map(String) : []);
        if (b.full) edge = { on: !!b.on, epoch: String(b.epoch || ""), hosts: new Set(list(b.hosts).map((x) => x.toLowerCase())), cleared: new Set(list(b.cleared)), banned: new Set(list(b.banned)) };
        else {
          if (!edge.epoch || b.epoch !== edge.epoch) return reply(409, { error: "send it in full", epoch: edge.epoch });
          if ("on" in b) edge.on = !!b.on;
          if (b.hosts) edge.hosts = new Set(list(b.hosts).map((x) => x.toLowerCase()));
          for (const k of ["cleared", "banned"]) { for (const ip of list(b.add?.[k])) edge[k].add(ip); for (const ip of list(b.del?.[k])) edge[k].delete(ip); }
        }
        reply(200, { ok: true, epoch: edge.epoch, on: edge.on, hosts: edge.hosts.size, cleared: edge.cleared.size, banned: edge.banned.size });
      });
    }
    if (req.method === "POST" && req.url === "/zones/remove") {
      return body(4096, ({ suffix: z }) => reply(200, { ok: true, removed: removeZone(String(z || "").toLowerCase()) }));
    }
    // a newer agent from your Aegis: checked, then it takes this file's place, and systemd starts it
    if (req.method === "POST" && req.url === "/update") {
      return body(2 * 1024 * 1024, ({ code, version }) => {
        if (typeof code !== "string" || !code.includes("startAgent")) return reply(400, { error: "that isn't an agent" });
        const self = cfg.agentFile || new URL(import.meta.url).pathname, next = self.replace(/\.m?js$/, "") + ".next.mjs";
        writeFileSync(next, code, { mode: 0o644 });
        try { execFileSync(process.execPath, ["--check", next], { stdio: "pipe", timeout: 30000 }); }
        catch (e) { rmSync(next, { force: true }); const lines = String(e.stderr || e.message).split("\n"); return reply(400, { error: "it doesn't parse: " + (lines.find((l) => /Error/.test(l)) || lines[0]) }); }
        if (existsSync(self)) writeFileSync(self + ".prev", readFileSync(self));
        renameSync(next, self);
        log(`updated to ${String(version || "?").slice(0, 20)}; restarting`);
        reply(200, { ok: true, from: VERSION, to: version || null });
        if (cfg.exitOnUpdate !== false) setTimeout(() => process.exit(0), 300);
      });
    }
    // this server's clock, right again ({truth: ms since 1970, read off the web by your Aegis}; -> {before, after, how})
    if (req.method === "POST" && req.url === "/clock") {
      return body(4096, ({ truth }) => {
        truth = Number(truth);
        if (!(truth > 1.7e12 && truth < 4.1e12)) return reply(400, { error: "that isn't a time" });
        // the true time from here on, on the monotonic clock (Date.now() is the one that's wrong)
        const t0 = performance.now(), real = () => truth + (performance.now() - t0), off = () => Date.now() - real();
        fixClock(off, real).then((r) => reply(200, r), (e) => reply(500, { error: e.message }));
      });
    }
    // into your Aegis's Machines: its link script, as root ({script}; -> {code, out})
    if (req.method === "POST" && req.url === "/fleet/link") {
      return body(512 * 1024, ({ script }) => {
        if (typeof script !== "string" || !script.startsWith("#!/bin/sh")) return reply(400, { error: "that isn't a link script" });
        const env = { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: "/root", LANG: "C.UTF-8", AEGIS_FROM_RELAY: "1" };
        const child = execFile("sh", ["-s"], { env, cwd: "/", timeout: 280000, maxBuffer: 4 * 1024 * 1024 }, (e, out, err) => {
          const text = `${out || ""}${err || ""}`.slice(-6000);
          log(`linked into Machines: ${e ? "failed (" + (e.code ?? e.signal) + ")" : "done"}`);
          reply(200, { ok: !e, code: e ? e.code ?? -1 : 0, out: text });
        });
        child.stdin.on("error", () => {});
        child.stdin.end(script);
      });
    }
    reply(404, { error: "not found" });
  });
  // NTP first (timedatectl, then whichever time service is there); only if the
  // clock is still off after that is it set by hand, to the time your Aegis sent
  async function fixClock(off, real) {
    const before = off(), how = [];
    const run = (cmd, args) => new Promise((ok) => execFile(cmd, args, { timeout: 20000, env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" } }, (e) => ok(!e)));
    if (Math.abs(before) < 2000) return { before, after: before, how: ["already right"] };
    if (cfg.clockCommands === false) return { before, after: before, how: ["not allowed here"] };
    if (await run("timedatectl", ["set-ntp", "true"])) how.push("ntp on");
    for (const svc of ["systemd-timesyncd", "chrony", "chronyd", "ntp", "ntpd"]) if (await run("systemctl", ["try-restart", svc])) { /* restarted only if it was running */ }
    for (let i = 0; i < 10 && Math.abs(off()) > 2000; i++) await new Promise((ok) => setTimeout(ok, 1000));
    if (Math.abs(off()) > 2000) {
      if (await run("date", ["-u", "-s", `@${(real() / 1000).toFixed(3)}`])) { how.push("set by hand"); await run("hwclock", ["--systohc"]); }
    }
    const after = off();
    log(`clock: was ${Math.round(before / 1000)} s off, now ${Math.round(after / 1000)} s (${how.join(", ") || "nothing worked"})`);
    return { before, after, how };
  }
  control.listen(cfg.controlPort, "127.0.0.1");
  return { front, control, stats, installCert, removeZone, zones, sites, close: () => { front.close(); control.close(); } };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
  startAgent(cfg);
}
