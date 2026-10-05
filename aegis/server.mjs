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
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from "node:fs";
import { join, extname } from "node:path";
import { networkInterfaces } from "node:os";
import { webcrypto, randomBytes, randomUUID, scryptSync, timingSafeEqual,
         createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { ml_kem768_x25519 as xwing } from "./vendor/pq.mjs";
import { APP, HOME, DATA, VERSION, Settings, writeJson } from "./config.mjs";
import { Burrow } from "../burrow/index.mjs";
import { Addons, AddonError } from "../burrow/addons.mjs";
import { health as bridgeHealth, submitToForge, adoptForge } from "./bridge.mjs";
import { Termix } from "./termix.mjs";
import { Pack } from "./pack.mjs";
import { listIntegrations, getIntegration, publicView, forgeDesktops, forgeAction, addonView } from "./integrations.mjs";

const settings = new Settings();
const LISTEN = { host: "127.0.0.1", port: 4310, ...settings.get("listen") };
if (process.env.AEGIS_PORT) LISTEN.port = Number(process.env.AEGIS_PORT);
if (process.env.AEGIS_BIND) LISTEN.host = process.env.AEGIS_BIND;
const TLS = settings.get("tls");
const COOKIE = settings.get("cookie") || "__Host-aegis";          // also the AEAD label of the token
const PLAIN_COOKIE = "aegis";                                      // the same token on plain HTTP
const GO = "aegis-go";                                             // one-shot: "the next / is Termix"
// Configurable under Settings → Sign-in (data/state.json).
const sessionTtl = () => Math.max(1, Math.min(365, Number(settings.get("sessionDays")) || 30)) * 864e5;
const SESSION_RENEW_MS = 24 * 60 * 60 * 1000;
const TICKET_TTL_MS = 60 * 1000;
const REVOKED_FILE = join(DATA, "revoked.json");
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const lockout = () => {
  const l = settings.get("lockout") || {};
  return { fails: Math.max(3, Math.min(50, Number(l.attempts) || 5)), windowMs: Math.max(1, Math.min(1440, Number(l.minutes) || 15)) * 60000 };
};

function log(...args) { console.log(new Date().toISOString(), ...args); }

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
for (const f of ["login.html", "setup.html", "home.html", "tunnels.html", "settings.html", "welcome.html",
                 "login.js", "common.js", "home.js", "tunnels.js", "settings.js", "welcome.js", "ui.css", "login.css",
                 "logos/aegis.svg", "logos/aegis-burrow.svg", "logos/burrow.svg", "logos/termix.svg", "logos/forge.svg"]) {
  FILES[f] = readFileSync(join(PUBLIC, f));
}
const TYPES = { ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".html": "text/html; charset=utf-8" };

// ---------- the pieces ----------

// Where cloudflared (on this machine) reaches us: the listen address itself,
// or loopback when we listen on every address.
const ORIGIN_HOST = ["0.0.0.0", "::", ""].includes(LISTEN.host) ? "127.0.0.1"
  : LISTEN.host.includes(":") ? `[${LISTEN.host}]` : LISTEN.host;
const origin = () => ({ url: `${TLS ? "https" : "http"}://${ORIGIN_HOST}:${LISTEN.port}`, insecure: !!TLS });
const burrow = new Burrow({ settings, dataDir: DATA, home: HOME, origin, forbiddenPorts: [LISTEN.port], log, version: VERSION });
const { tunnels, cloudflare } = burrow;
const burrowOn = () => burrow.on;
// Burrow's addons: the same format as Selkies Forge's (burrow/addons.mjs).
const addons = new Addons({
  dir: join(DATA, "addons"), registry: join(DATA, "addons.json"), version: VERSION, log, tunnels,
  env: () => {
    const e = { ADDON_HOST_URL: `${TLS ? "https" : "http"}://${ORIGIN_HOST}:${LISTEN.port}/`, ADDON_BIND: LISTEN.host,
                BURROW_SOCKET: join(DATA, "control.sock") };
    // the Selkies Forge on this machine, when one registered: addons that talk to it find it
    const f = listIntegrations().find((i) => i.kind === "selkies-forge");
    if (f) Object.assign(e, { FORGE_URL: f.url || "", FORGE_API: f.api || "", ...(f.home ? { FORGE_HOME: f.home } : {}) });
    return e;
  },
});
// Both ways: once the Forge has us as an addon, we add it as one of ours.
const bridgeTick = () => adoptForge({ addons, log }).catch((e) => log("bridge:", e.message));
setTimeout(bridgeTick, 20000);
setInterval(bridgeTick, 120000);
const termix = new Termix({ settings, log });
const pack = new Pack({ settings, termix, log });

const mainHost = () => settings.get("domain")?.mainHost?.toLowerCase() || null;

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
const clientIp = (req) => (viaProxy(req) ? req.headers["cf-connecting-ip"] : req.socket.remoteAddress) || "?";
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
  const ours = [COOKIE, PLAIN_COOKIE, GO, "__Host-" + GO].map((n) => n + "=");
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

function renewalCookie(req) {
  const s = sessionOf(req);
  if (!s || s.exp - Date.now() > sessionTtl() - SESSION_RENEW_MS) return null;
  return sessionCookie(req, s.sid || b64u(randomBytes(12)));
}

// ---------- single sign-on tickets (dashboard -> tunnel host) ----------

const usedTickets = new Map(); // n -> expiry
const sealTicket = (host, sid) => seal({ h: host, sid, exp: Date.now() + TICKET_TTL_MS, n: b64u(randomBytes(12)) }, "tgate-sso");
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
  res.writeHead(status, { ...SEC_HEADERS, ...sec, ...headers });
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
  return isLoopback(req.socket.remoteAddress) && !req.headers["cf-connecting-ip"] && !req.headers["x-forwarded-for"];
}

// ---------- gate routes (any host) ----------

async function handleGate(req, res, path, url, host, isMain) {
  const hasDomain = !!mainHost();
  if (path === "/__gate/health") return sendJson(res, 200, { ok: true, app: "aegis-burrow", version: VERSION, burrow: burrow.on });
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

  if (path === "/__gate/login" && req.method === "GET") {
    if (isAuthed(req)) return send(res, 302, "", { Location: safeNext(url.searchParams.get("next"), "/") });
    // With a domain, tunnel hosts sign in through the dashboard, so one login covers them all.
    if (!isMain && hasDomain) return send(res, 302, "", { Location: ssoUrl(host, url.searchParams.get("next")) });
    return page(res, "login.html");
  }
  if (path === "/__gate/auth" && req.method === "POST") {
    const ip = clientIp(req);
    if (tooManyFails(ip)) {
      log("auth throttled", ip, host);
      return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
    }
    let creds;
    try { creds = await unwrapSealed(await readJsonBody(req)); }
    catch (e) {
      recordFail(ip); log("auth decrypt failed", ip, e.message);
      return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." });
    }
    if (!checkCredentials(creds.username, creds.password)) {
      recordFail(ip); log("auth bad credentials", ip, host);
      return sendJson(res, 401, { error: "Invalid username or password." });
    }
    fails.delete(ip); log("auth ok", ip, host);
    return sendJson(res, 200, { ok: true, next: safeNext(creds.next, "/") }, { "Set-Cookie": sessionCookie(req, b64u(randomBytes(12))) });
  }
  if (path === "/__gate/logout") {
    const s = sessionOf(req);
    if (isMain && s) { revoke(s.sid); log("logout", clientIp(req), "sid revoked"); }
    const to = isMain ? "/__gate/login" : hasDomain ? `https://${mainHost()}/__gate/logout` : "/";
    return send(res, 302, "", { Location: to, "Set-Cookie": clearSessionCookie(req) });
  }
  if (!isMain && path === "/__gate/sso/callback" && req.method === "GET") {
    const t = openTicket(url.searchParams.get("t"), host);
    if (!t) {
      log("sso ticket refused", clientIp(req), host);
      return messagePage(res, 403, "Sign-in expired", 'That sign-in link expired. <a href="/">Try again</a>.');
    }
    return send(res, 302, "", { Location: safeNext(url.searchParams.get("next"), "/"), "Set-Cookie": sessionCookie(req, t.sid) });
  }
  if (!isMain) return send(res, 404, "Not found");

  // ---- dashboard: hand a login tunnel a ticket (asks for the login first if needed) ----
  if (path === "/__gate/sso" && req.method === "GET") {
    const to = String(url.searchParams.get("to") || "").toLowerCase();
    const port = burrowOn() ? tunnels.matchHost(to) : null;
    if (port === null || !tunnels.get(port)) return send(res, 404, "Not found");
    const s = sessionOf(req);
    if (!s) return send(res, 302, "", { Location: "/__gate/login?next=" + encodeURIComponent(req.url) });
    const next = safeNext(url.searchParams.get("next"), "/");
    return send(res, 302, "", { Location: `https://${to}/__gate/sso/callback?t=${sealTicket(to, s.sid)}&next=${encodeURIComponent(next)}` });
  }

  // ---- dashboard, signed in only ----
  if (!isAuthed(req)) {
    if (path.startsWith("/__gate/api/")) return sendJson(res, 401, { error: "login required" });
    return send(res, 302, "", { Location: "/__gate/login?next=" + encodeURIComponent(safeNext(req.url, "/")) });
  }
  if (path === "/__gate/choose" || path === "/__gate/home") return page(res, "home.html");
  if (path === "/__gate/open/termix") {
    if (!settings.get("termix")) return send(res, 302, "", { Location: "/__gate/settings#termix" });
    return send(res, 302, "", { Location: "/", "Set-Cookie": `${goName(req)}=termix; ${cookieAttrs(req, 30).replace("SameSite=Lax", "SameSite=Strict")}` });
  }
  if (path === "/__gate/tunnels") return page(res, "tunnels.html");
  if (path === "/__gate/settings") return page(res, "settings.html");
  if (path === "/__gate/welcome") return page(res, "welcome.html");
  if (path.startsWith("/__gate/api/")) return handleApi(req, res, path, url);
  return send(res, 404, "Not found");
}

// ---------- dashboard API (signed in) ----------

function me(req) {
  const s = sessionOf(req);
  const d = settings.get("domain");
  return {
    app: "aegis-burrow", version: VERSION, title: settings.get("title"), user: s?.u || null,
    mode: tunnels.mode, pattern: tunnels.pattern(),
    domain: d ? { mainHost: d.mainHost, managed: !!d.managed } : null,
    termix: !!settings.get("termix"),
    integrations: listIntegrations().map((i) => publicView(i, tunnels)),
    tunnels: tunnels.tunnels.size,
    modules: { burrow: burrowOn() },
    home: settings.get("home") || null,
    login: { subtitle: (settings.get("login") || {}).subtitle || "Secure channel" },
    sessionDays: sessionTtl() / 864e5, lockout: { attempts: lockout().fails, minutes: lockout().windowMs / 60000 },
    pack: pack.status(),
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
  if ("modules" in p) burrow.setOn(p.modules?.burrow !== false);
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
    if (path === "/__gate/api/prefs" && req.method === "POST") { savePrefs(await readJsonBody(req)); return sendJson(res, 200, me(req)); }
    if (path === "/__gate/api/pack" && req.method === "GET") return sendJson(res, 200, pack.status());
    if (path === "/__gate/api/pack" && req.method === "POST") {
      const body = await readJsonBody(req);
      if (body.skip) { pack.skip(); return sendJson(res, 200, pack.status()); }
      let choice;
      try { choice = await unwrapSealed(body); } catch { return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." }); }
      return sendJson(res, 200, pack.run(choice));
    }
    // Burrow: the tunnel API (burrow/index.mjs)
    const br = await burrow.handle(req.method, path.slice("/__gate/api".length), () => readJsonBody(req));
    if (br) return br.body !== undefined ? send(res, br.status, br.body, br.headers) : sendJson(res, br.status, br.json);
    if (path === "/__gate/api/addon" && req.method === "GET") {
      return sendJson(res, 200, addonView({ tunnels, control: burrow.controlView(), burrow: burrow.status() }));
    }
    if (path.startsWith("/__gate/api/addons") || path.startsWith("/__gate/api/bridge")) return await handleAddons(req, res, path, url);

    // integrations
    if (path === "/__gate/api/integrations") return sendJson(res, 200, { integrations: listIntegrations().map((i) => publicView(i, tunnels)) });
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
        return sendJson(res, 200, { ...(await forgeDesktops(integ, tunnels)), integration: publicView(integ, tunnels) });
      }
      if (im[3] && req.method === "POST") {
        await forgeAction(integ, im[3], im[4]);
        log("integration", integ.id, im[4], im[3]);
        return sendJson(res, 200, { ok: true });
      }
      if (!im[2]) return sendJson(res, 200, publicView(integ, tunnels));
    }

    // Cloudflare / domain
    if (path === "/__gate/api/cf" && req.method === "GET") return sendJson(res, 200, cloudflare.state());
    if (path === "/__gate/api/cf/login" && req.method === "POST") return sendJson(res, 200, await cloudflare.startLogin());
    if (path === "/__gate/api/cf/cancel" && req.method === "POST") return sendJson(res, 200, cloudflare.cancelLogin());
    if (path === "/__gate/api/cf/forget" && req.method === "POST") return sendJson(res, 200, cloudflare.forgetCert());
    if (path === "/__gate/api/cf/link" && req.method === "POST") return sendJson(res, 200, await cloudflare.link((await readJsonBody(req)).label));
    if (path === "/__gate/api/cf/unlink" && req.method === "POST") return sendJson(res, 200, await cloudflare.unlink());

    // Termix
    if (path === "/__gate/api/termix" && req.method === "GET") return sendJson(res, 200, await termix.status());
    if (path === "/__gate/api/termix/install" && req.method === "POST") return sendJson(res, 200, termix.install());
    if (path === "/__gate/api/termix/remove" && req.method === "POST") return sendJson(res, 200, await termix.remove());

    // account
    if (path === "/__gate/api/password" && req.method === "POST") {
      const ip = clientIp(req);
      if (tooManyFails(ip)) return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
      let f;
      try { f = await unwrapSealed(await readJsonBody(req)); } catch { return sendJson(res, 400, { error: "Secure handshake failed. Reload and try again." }); }
      if (!checkCredentials(settings.auth().username, f.current)) { recordFail(ip); return sendJson(res, 401, { error: "The current password is wrong." }); }
      const username = String(f.username || settings.auth().username).trim();
      if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) return sendJson(res, 400, { error: "Username: 2-64 letters, digits, . _ @ -" });
      if (String(f.password || "").length < 10) return sendJson(res, 400, { error: "Use at least 10 characters." });
      setPassword(username, f.password);
      log("password changed from", ip, "- every other session is signed out");
      return sendJson(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, b64u(randomBytes(12))) });
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
    if (path === "/__gate/api/addons/scan" && req.method === "GET") return ok(await addons.scan(url.searchParams.get("fresh") ? 0 : 60000));
    if (path === "/__gate/api/addons/add" && req.method === "POST") return ok({ addon: await addons.add((await readJsonBody(req)).source) });
    const j = /^\/__gate\/api\/addons\/jobs\/([0-9a-f]{12})(\/cancel)?$/.exec(path);
    if (j) {
      const job = addons.job(j[1]);
      if (j[2] && req.method === "POST") { job.cancel(); return ok(job.view(1e9)); }
      return ok(job.view(Number(url.searchParams.get("since")) || 0));
    }
    const m = /^\/__gate\/api\/addons\/([a-z0-9-]{2,40})\/(image|install|update|uninstall|remove|action|check|share)$/.exec(path);
    if (m) {
      const [, id, op] = m;
      if (op === "image") { const im = addons.image(id, url.searchParams.get("path")); return send(res, 200, im.body, { "Content-Type": im.type, "Cache-Control": "private, max-age=86400", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" }); }
      if (req.method !== "POST") return sendJson(res, 405, { error: "POST" });
      const b = await readJsonBody(req);
      if (op === "install") {
        const job = addons.install(id, b.settings);
        if (id === "selkies-forge") followForge(job.id);
        return ok({ job });
      }
      if (op === "update") return ok({ job: addons.update(id) });
      if (op === "uninstall") return ok({ job: addons.uninstall(id, b.keep_data !== false) });
      if (op === "remove") return ok(addons.remove(id));
      if (op === "action") return ok({ job: addons.action(id, b.action) });
      if (op === "check") return ok(await addons.checkUpdates(id));
      if (op === "share") return ok({ tunnel: await addons.share(id, b.on !== false, b.access === "public" ? "public" : "login") });
    }
    if (path === "/__gate/api/bridge" && req.method === "GET") return ok(await bridgeHealth({ burrow, addons }));
    if (path === "/__gate/api/bridge/connect" && req.method === "POST") {
      const out = { forge: await submitToForge({ log }) };
      const local = await adoptForge({ addons, log }).catch((e) => ({ error: e.message }));
      if (local) out.local = local;
      return ok(out);
    }
    return sendJson(res, 404, { error: "not found" });
  } catch (e) {
    if (!(e instanceof AddonError)) log("addons:", e.message);
    return sendJson(res, 400, { error: e.message });
  }
}

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

function proxyUpgrade(req, socket, head) {
  const up = termixUpstream();
  if (!up) { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }
  const mod = up.https ? httpsRequest : httpRequest;
  const r = mod({ host: up.host, port: up.port, method: req.method, path: req.url, headers: upstreamHeaders(req), rejectUnauthorized: false });
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

function tunnelRequest(port, req, res, path, url, host) {
  const t = tunnels.get(port);
  if (!t) return notFoundPage(res, "none");
  if (path.startsWith("/__gate/")) return handleGate(req, res, path, url, host, false);
  if (!t.enabled) return notFoundPage(res, "paused");
  if (t.access === "login" && !isAuthed(req)) {
    const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
    if (!wantsHtml) return sendJson(res, 401, { error: "login required" });
    return send(res, 302, "", { Location: mainHost() ? ssoUrl(host, req.url) : "/__gate/login?next=" + encodeURIComponent(safeNext(req.url, "/")) });
  }
  tunnels.proxy(port, req, res, { stripCookie: stripGateCookie });
}

// ---------- server ----------

async function handler(req, res) {
  res.req = req;
  const host = hostOf(req);
  const url = new URL(req.url || "/", "http://x");
  const path = url.pathname;
  try {
    const port = burrow.matchHost(host);
    if (port !== null) return tunnelRequest(port, req, res, path, url, host);
    const isMain = host === mainHost() || isLocalName(host);
    if (!isMain) return send(res, 404, "Not found");
    if (path.startsWith("/__gate/")) return await handleGate(req, res, path, url, host, true);
    if (!settings.auth()) return send(res, 302, "", { Location: "/__gate/setup" + url.search });
    if (!isAuthed(req)) {
      const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
      return wantsHtml
        ? send(res, 302, "", { Location: "/__gate/login" + (path === "/" ? "" : "?next=" + encodeURIComponent(safeNext(req.url, "/"))) })
        : sendJson(res, 401, { error: "login required" });
    }
    const renew = req.method === "GET" && isPageLoad(req) ? renewalCookie(req) : null;
    const withRenew = renew ? { "Set-Cookie": renew } : {};
    if (!termixUpstream()) {
      if (path === "/" && req.method === "GET") return page(res, "home.html", withRenew);
      return send(res, 302, "", { Location: "/" });
    }
    if (path === "/" && req.method === "GET" && isPageLoad(req)) {
      if (parseCookies(req.headers.cookie)[goName(req)] !== "termix") return page(res, "home.html", withRenew);
      return proxy(req, res, { setCookie: [`${goName(req)}=; ${cookieAttrs(req, 0)}`, renew].filter(Boolean) });
    }
    proxy(req, res, renew ? { setCookie: renew } : undefined);
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
  const host = hostOf(req);
  const port = burrow.matchHost(host);
  if (port !== null) {
    const t = tunnels.get(port);
    if (!t || !t.enabled) { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }
    if (t.access === "login" && !isAuthed(req)) { socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n"); return; }
    return tunnels.proxyUpgrade(port, req, socket, head, { stripCookie: stripGateCookie });
  }
  if (!(host === mainHost() || isLocalName(host)) || !isAuthed(req)) { socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n"); return; }
  proxyUpgrade(req, socket, head);
});

// ---------- the local control socket (Burrow's, see burrow/index.mjs) ----------

burrow.listenControl(join(DATA, "control.sock"));
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { burrow.stop(); process.exit(0); });

server.listen(LISTEN.port, LISTEN.host, () => {
  const scheme = TLS ? "https" : "http";
  const local = `${scheme}://${LISTEN.host === "0.0.0.0" || LISTEN.host === "::" ? "127.0.0.1" : LISTEN.host}:${LISTEN.port}`;
  log(`aegis × burrow ${VERSION} on ${local}${mainHost() ? ` (dashboard https://${mainHost()})` : ""}, tunnels: ${tunnels.mode}`);
  try { writeJson(join(DATA, "runtime.json"), { pid: process.pid, url: local + "/", started: Date.now(), version: VERSION, mainHost: mainHost() }, 0o644); }
  catch { /* read-only data dir: fine */ }
  if (!settings.auth()) {
    const t = settings.setupToken();
    log(`first run: create the login at ${local}/__gate/setup${t ? `?t=${t}` : ""}`);
  }
});
