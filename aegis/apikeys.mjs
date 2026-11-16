// Developer API keys: programs and scripts that drive Aegis × Burrow over HTTPS.
//
// A key looks like  aegis_<id>_<secret>  (id: 10 hex, secret: 32 random bytes,
// base64url). Only the SHA-256 of the secret is kept, in data/apikeys.json
// (mode 600), so the key is shown once, when it is made or rolled, and never again.
//
// A key carries scopes (what it may change), which apps it opens, an optional
// expiry, an optional list of addresses it works from, and a rate limit. It is
// sent as  Authorization: Bearer <key>  or  X-Aegis-Key: <key>, and the gate strips
// it before anything is passed on to an app.
//
// What no key can do, whatever its scopes: make, change or see other keys, change
// the login, or read the askpass of a root job. A leaked key can always be revoked
// from the dashboard by the person who signed in, and it can't lock them out.
//
// data/apikeys.json: {enabled, keys: [{id, name, note, hash, scopes, apps, expires,
//                     ips, rate, disabled, created, rolled, last, uses}], log: [...]}

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { BlockList, isIP } from "node:net";

export const SCOPES = {
  full:     { name: "Everything", note: "Every scope below, and every app. The same as you, signed in (except keys and the login)." },
  read:     { name: "Read", note: "Every GET: status, tunnels, addons, machines, domains, settings, activity." },
  tunnels:  { name: "Tunnels", note: "Create, change, switch off and remove Burrow tunnels; Burrow on or off." },
  addons:   { name: "Addons", note: "Install, update, roll back and remove addons, run their actions, and their own APIs (/x/<id>)." },
  machines: { name: "Machines", note: "Link, probe and manage machines (Fleet): install apps, move and copy files, standby." },
  network:  { name: "Network", note: "Domains, Cloudflare, the VPS relay, Serveo and the shield (bans, allow list)." },
  system:   { name: "System", note: "Updates and rollback, themes, preferences, Termix, notices and the pack." },
  apps:     { name: "Apps", note: "Open the apps behind the login with the key: tunnels set to \"login\", and apps under the dashboard." },
};
export const SCOPE_IDS = Object.keys(SCOPES);
const LOG_KEEP = 300;
const KEY_RE = /^aegis_([0-9a-f]{10})_([A-Za-z0-9_-]{43})$/;

// Which scope a call needs. Paths come without their /__gate/api or /__gate/v1 prefix.
// "never": no key, whatever its scopes. GETs only need "read", except where noted.
export function scopeFor(method, path) {
  if (/^\/(keys|devkeys)(\/|$)/.test(path)) return "never";
  if (/^\/(askpass)(\/|$)/.test(path) || /^\/addons\/[a-z0-9-]+\/runspec$/.test(path) || /^\/addons\/jobs\/[0-9a-f]{12}\/(line|done)$/.test(path)) return "never";
  if (/^\/(password|setup)$/.test(path)) return "never";
  if (method === "GET" || method === "HEAD") return "read";
  if (/^\/(tunnels|ports|module)(\/|$)/.test(path)) return "tunnels";
  if (/^\/(addons?|bridge|x|integrations)(\/|$)/.test(path)) return "addons";
  if (/^\/fleet(\/|$)/.test(path)) return "machines";
  if (/^\/(cf|domains|dns|relay|serveo|shield|ipintel)(\/|$)/.test(path)) return "network";
  return "system";
}

const clean = (v, n) => String(v ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, n);
const sha = (s) => createHash("sha256").update(s).digest();

export class KeyError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; } }

export class ApiKeys {
  constructor({ file, log }) {
    this.file = file;
    this.log = log || (() => {});
    let d = {};
    try { d = JSON.parse(readFileSync(file, "utf8")); } catch { /* none yet */ }
    this.enabled = d.enabled === true;
    this.keys = Array.isArray(d.keys) ? d.keys : [];
    this.events = Array.isArray(d.log) ? d.log : [];
    this.windows = new Map();          // id -> {start, n}: this minute's requests
    this.dirty = false;
    this.timer = setInterval(() => this.flush(), 30e3);
    this.timer.unref?.();
  }
  save() { this.dirty = true; this.flush(); }
  flush() {
    if (!this.dirty) return;
    this.dirty = false;
    try {
      writeFileSync(this.file + ".tmp", JSON.stringify({ enabled: this.enabled, keys: this.keys, log: this.events.slice(0, LOG_KEEP) }, null, 1), { mode: 0o600 });
      renameSync(this.file + ".tmp", this.file);
    } catch (e) { this.log("api keys: could not save", e.message); }
  }
  stop() { clearInterval(this.timer); this.flush(); }

  // ---- what the dashboard shows (never a hash)
  viewOf(k) {
    const now = Date.now();
    const status = k.disabled ? "off" : k.expires && k.expires <= now ? "expired" : "on";
    return { id: k.id, name: k.name, note: k.note || "", prefix: `aegis_${k.id}_${k.tail ? "…" + k.tail : "…"}`, scopes: k.scopes, apps: k.apps,
             expires: k.expires || null, ips: k.ips || [], rate: k.rate, disabled: !!k.disabled, status,
             created: k.created, createdBy: k.createdBy || null, rolled: k.rolled || null, last: k.last || null, uses: k.uses || 0 };
  }
  view() {
    return { enabled: this.enabled, keys: this.keys.map((k) => this.viewOf(k)), scopes: SCOPES, log: this.events.slice(0, 100) };
  }
  get(id) { const k = this.keys.find((x) => x.id === id); if (!k) throw new KeyError("No such key.", 404); return k; }

  setEnabled(on) { this.enabled = !!on; this.save(); return this.view(); }

  // ---- making and changing keys (the dashboard and the command line only)
  cleanSpec(b, old = {}) {
    const out = {};
    if (!old.id || "name" in b) {
      out.name = clean(b.name, 60);
      if (!out.name) throw new KeyError("Give the key a name, so you know later what uses it.");
    }
    if ("note" in b) out.note = clean(b.note, 200);
    if (!old.id || "scopes" in b) {
      const s = [...new Set((Array.isArray(b.scopes) ? b.scopes : []).map(String))].filter((x) => SCOPES[x]);
      if (!s.length) throw new KeyError("Pick what the key may do (at least one scope).");
      out.scopes = s.includes("full") ? ["full"] : s;
    }
    if (!old.id || "apps" in b) {
      if (b.apps === undefined || b.apps === "all") out.apps = "all";
      else if (Array.isArray(b.apps)) out.apps = [...new Set(b.apps.map((x) => clean(x, 80)).filter((x) => /^(tunnel:\d{1,6}|app:[a-z0-9-]{1,40})$/.test(x)))].slice(0, 200);
      else throw new KeyError("Apps: \"all\" or a list like [\"tunnel:8080\", \"app:termix\"].");
    }
    if (!old.id || "expires" in b) {
      if (b.expires === null || b.expires === undefined || b.expires === "" || b.expires === 0) out.expires = null;
      else if (typeof b.expires === "string" && /^\d+d$/.test(b.expires)) out.expires = Date.now() + Number(b.expires.slice(0, -1)) * 864e5;
      else {
        const t = Number(b.expires) || Date.parse(b.expires);
        if (!t || t <= Date.now()) throw new KeyError("The expiry has to be in the future.");
        out.expires = t;
      }
    }
    if (!old.id || "ips" in b) {
      const list = (Array.isArray(b.ips) ? b.ips : String(b.ips || "").split(/[\s,]+/)).map((x) => clean(x, 64)).filter(Boolean).slice(0, 50);
      for (const x of list) if (!cidrOk(x)) throw new KeyError(`"${x}" isn't an address or a range (like 203.0.113.7 or 10.0.0.0/8).`);
      out.ips = list;
    }
    if (!old.id || "rate" in b) {
      const r = b.rate === undefined || b.rate === null || b.rate === "" ? 600 : Math.round(Number(b.rate));
      if (!(r >= 0 && r <= 100000)) throw new KeyError("Rate limit: 0 (none) to 100000 requests a minute.");
      out.rate = r;
    }
    if ("disabled" in b) out.disabled = !!b.disabled;
    return out;
  }
  newSecret(k) {
    const secret = randomBytes(32).toString("base64url");
    k.hash = sha(secret).toString("hex");
    k.tail = secret.slice(-4);
    return `aegis_${k.id}_${secret}`;
  }
  create(b, by) {
    if (this.keys.length >= 100) throw new KeyError("That's 100 keys already. Remove some first.");
    const spec = this.cleanSpec(b || {});
    let id;
    do id = randomBytes(5).toString("hex"); while (this.keys.some((k) => k.id === id));
    const k = { id, note: "", ...spec, disabled: false, created: Date.now(), createdBy: by || null, last: null, uses: 0 };
    const key = this.newSecret(k);
    this.keys.unshift(k);
    this.enabled = true;               // making a key means you want the API on
    this.record(k, { event: "created", by });
    this.save();
    return { key, ...this.viewOf(k) };
  }
  update(id, b, by) {
    const k = this.get(id);
    Object.assign(k, this.cleanSpec(b || {}, k));
    this.record(k, { event: "disabled" in (b || {}) ? (k.disabled ? "switched off" : "switched on") : "changed", by });
    this.save();
    return this.viewOf(k);
  }
  roll(id, by) {
    const k = this.get(id);
    const key = this.newSecret(k);
    k.rolled = Date.now();
    this.record(k, { event: "rolled (the old key stopped working)", by });
    this.save();
    return { key, ...this.viewOf(k) };
  }
  remove(id, by) {
    const k = this.get(id);
    this.keys = this.keys.filter((x) => x !== k);
    this.windows.delete(id);
    this.record(k, { event: "revoked", by });
    this.save();
    return this.view();
  }
  removeAll(by) {
    for (const k of this.keys) this.record(k, { event: "revoked", by });
    this.keys = []; this.windows.clear();
    this.save();
    return this.view();
  }

  // ---- the gate: who is this
  // -> {key} for a good key; {error, status} for a bad one; null when the request has none
  check(req, ip) {
    const raw = tokenOf(req);
    if (!raw) return null;
    const m = KEY_RE.exec(raw);
    if (!m) return { error: "That isn't an Aegis API key.", status: 401 };
    const k = this.keys.find((x) => x.id === m[1]);
    const ok = k && k.hash && timingSafeEqual(sha(m[2]), Buffer.from(k.hash, "hex"));
    if (!ok) return { error: "Unknown or revoked API key.", status: 401 };
    if (!this.enabled) return { error: "The API is switched off (Settings → Developer).", status: 403, key: k };
    if (k.disabled) return { error: "This API key is switched off.", status: 403, key: k };
    if (k.expires && k.expires <= Date.now()) return { error: "This API key has expired.", status: 401, key: k };
    if (k.ips?.length && !ipAllowed(k.ips, ip)) return { error: `This API key doesn't work from ${ip}.`, status: 403, key: k };
    if (k.rate) {
      const now = Date.now(), w = this.windows.get(k.id);
      if (!w || now - w.start >= 60e3) this.windows.set(k.id, { start: now, n: 1 });
      else if (++w.n > k.rate) return { error: `Rate limit: ${k.rate} requests a minute.`, status: 429, key: k, retry: Math.ceil((w.start + 60e3 - now) / 1000) };
    }
    return { key: k };
  }
  may(k, method, path) {
    const need = scopeFor(method, path);
    if (need === "never") return false;
    if (k.scopes.includes("full")) return true;
    if (need === "read") return k.scopes.includes("read") || k.scopes.some((s) => s !== "apps");
    return k.scopes.includes(need);
  }
  // an app behind the login: "tunnel:<port>" or "app:<id>"
  opens(k, app) {
    if (!(k.scopes.includes("full") || k.scopes.includes("apps"))) return false;
    return k.apps === "all" || (Array.isArray(k.apps) && k.apps.includes(app));
  }
  // a use, for "last used" and the key's activity
  // (app: an app opened with it; only "last used", never the activity list: apps make many calls)
  used(k, { ip, method, path, status, ua, app }) {
    k.last = { at: Date.now(), ip, method, path: String(path).slice(0, 160), status };
    k.uses = (k.uses || 0) + 1;
    if (!app && (method !== "GET" || status >= 400)) this.record(k, { event: `${method} ${String(path).slice(0, 160)}`, ip, status, ua: clean(ua, 120) });
    this.dirty = true;
  }
  record(k, e) {
    this.events.unshift({ t: Date.now(), key: k.id, name: k.name, ...e });
    if (this.events.length > LOG_KEEP) this.events.length = LOG_KEEP;
    this.dirty = true;
  }
}

// Authorization: Bearer aegis_…  or  X-Aegis-Key: aegis_…
export function tokenOf(req) {
  const x = req.headers["x-aegis-key"];
  if (typeof x === "string" && x) return x.trim();
  const a = String(req.headers.authorization || "");
  const m = /^Bearer\s+(aegis_\S+)$/i.exec(a);
  return m ? m[1] : null;
}
// gone before anything is passed on to an app (an app's own Authorization stays)
export function stripKey(req) {
  delete req.headers["x-aegis-key"];
  if (/^Bearer\s+aegis_/i.test(String(req.headers.authorization || ""))) delete req.headers.authorization;
}

function cidrOk(x) {
  const [a, bits] = x.split("/");
  const v = isIP(a);
  if (!v) return false;
  if (bits === undefined) return true;
  const n = Number(bits);
  return /^\d{1,3}$/.test(bits) && n >= 0 && n <= (v === 4 ? 32 : 128);
}
function ipAllowed(list, ip) {
  ip = String(ip || "").replace(/^::ffff:/, "");
  const v = isIP(ip);
  if (!v) return false;
  const bl = new BlockList();
  for (const x of list) {
    const [a, bits] = x.split("/"), t = isIP(a) === 6 ? "ipv6" : "ipv4";
    try { bits === undefined ? bl.addAddress(a, t) : bl.addSubnet(a, Number(bits), t); } catch { /* skipped */ }
  }
  return bl.check(ip, v === 6 ? "ipv6" : "ipv4");
}
