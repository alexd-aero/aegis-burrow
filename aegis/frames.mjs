// Termix's plugin frames (Termix 26.11.2+, plugin API 2).
//
// Termix draws every plugin screen (the SSH terminal included) in an iframe
// with sandbox="allow-scripts": an opaque origin, so nothing it asks for
// carries a cookie, the gate's sign-in included. What such a frame asks for
// by itself:
//   GET  /plugin-assets/**          the plugin's own files and Termix's frame
//                                   runtime: static, public in Termix too
//   any  /plugin-api/<id>/**        "Authorization: Bearer <frame key>"
//   WS   /plugin-ws/<id>/**         the key in Sec-WebSocket-Protocol "termix.jwt.<key>"
// Everything else a frame needs goes through the page that holds it, which
// is signed in here as usual.
//
// A frame key gets through only when Termix minted it for a page signed in
// here: the gate sees the answer to POST /plugins/frame-tokens (or
// /plugins/<id>/frame-token) go by and keeps a hash of each key, the plugin it
// opens, until it runs out, and the sign-in that asked. A key for another
// plugin, an expired one or one from a session that was signed out is refused
// before Termix ever sees it. Only hashes are kept, also on disk, so a restart
// of the gate doesn't cut off frames that are open.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";

export const TOKEN_ASK = /^\/plugins\/(?:frame-tokens|([a-z][a-z0-9-]*)\/frame-token)$/;
const API = /^\/plugin-api\/([a-z][a-z0-9-]*)(?:\/|$)/;
const WS = /^\/plugin-ws\/([a-z][a-z0-9-]*)(?:\/|$)/;
const ASSETS = /^\/plugin-assets\/[^\\]*$/;
const PROTOCOL = "termix.jwt.";
const ID = /^[a-z][a-z0-9-]*$/;
const MAX_TTL_MS = 15 * 60e3;   // Termix gives 5 minutes; never trust a longer answer than this
const GRACE_MS = 30e3;          // clocks and a request already on its way
const MAX_KEYS = 5000;

const hash = (t) => createHash("sha256").update(String(t)).digest("base64url");

export function bearerOf(req) {
  const m = /^Bearer\s+(\S{16,4096})$/i.exec(String(req.headers?.authorization || ""));
  return m ? m[1] : null;
}
export function wsKeyOf(req) {
  for (const p of String(req.headers?.["sec-websocket-protocol"] || "").split(",")) {
    const v = p.trim();
    if (v.startsWith(PROTOCOL) && v.length > PROTOCOL.length + 16 && v.length < 4096) return v.slice(PROTOCOL.length);
  }
  return null;
}

export class FrameKeys {
  // alive(session): is the sign-in that asked for a key still good?
  constructor({ file = null, now = Date.now, alive = () => true } = {}) {
    this.file = file; this.now = now; this.alive = alive;
    this.keys = new Map();      // sha256(key) -> { id, exp, s }
    this.saveTimer = null;
    if (file) {
      try {
        for (const [h, k] of Object.entries(JSON.parse(readFileSync(file, "utf8"))))
          if (k && ID.test(k.id) && k.exp > now()) this.keys.set(h, k);
      } catch { /* none yet */ }
    }
  }

  isTokenAsk(method, path) { return method === "POST" && TOKEN_ASK.test(path); }

  // Termix's answer to a signed-in page's ask; s is that page's session
  learn(path, body, s) {
    const m = TOKEN_ASK.exec(path);
    if (!m) return 0;
    let j;
    try { j = JSON.parse(String(body)); } catch { return 0; }
    const entries = m[1] ? [[m[1], j]] : Object.entries(j?.tokens || {});
    let n = 0;
    for (const [id, e] of entries) {
      if (!ID.test(id) || typeof e?.token !== "string" || e.token.length < 16 || e.token.length > 4096) continue;
      const ttl = Math.min(MAX_TTL_MS, Math.max(0, Number(e.expiresIn) || 300) * 1000 + GRACE_MS);
      this.keys.set(hash(e.token), { id, exp: this.now() + ttl, s: s ? { sid: s.sid || null, exp: s.exp || 0, e: s.e ?? null } : null });
      n++;
    }
    if (n) { this.prune(); this.save(); }
    return n;
  }

  // the plugin a key opens, when it is good
  pluginOf(key) {
    if (!key) return null;
    const k = this.keys.get(hash(key));
    if (!k) return null;
    if (k.exp <= this.now() || !this.alive(k.s)) { this.keys.delete(hash(key)); return null; }
    return k.id;
  }

  // What a frame may ask for without the gate's cookie: "asset", "key" or null.
  // path is the URL's pathname (already parsed).
  allows(req, path, { ws = false } = {}) {
    if (ws) {
      const m = WS.exec(path);
      return m && this.pluginOf(wsKeyOf(req)) === m[1] ? "key" : null;
    }
    if ((req.method === "GET" || req.method === "HEAD") && ASSETS.test(path) && !path.split("/").includes("..")) return "asset";
    const m = API.exec(path);
    return m && this.pluginOf(bearerOf(req)) === m[1] ? "key" : null;
  }

  prune() {
    const now = this.now();
    for (const [h, k] of this.keys) if (k.exp <= now) this.keys.delete(h);
    while (this.keys.size > MAX_KEYS) this.keys.delete(this.keys.keys().next().value);
  }

  save() {
    if (!this.file || this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      try { writeFileSync(this.file + ".tmp", JSON.stringify(Object.fromEntries(this.keys)), { mode: 0o600 }); renameSync(this.file + ".tmp", this.file); }
      catch { /* a restart then only waits for the next renewal */ }
    }, 1000);
    this.saveTimer.unref?.();
  }
}
