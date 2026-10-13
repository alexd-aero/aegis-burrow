// The Worker front: tunnel names two levels deep (radio.tunnel.example.com)
// on Cloudflare, free, with no open port and no server of your own.
//
// Cloudflare's free certificate covers *.example.com but not
// *.tunnel.example.com. A Workers Custom Domain, though, comes with an edge
// certificate of its own for exactly that name, at any depth, at no cost
// (developers.cloudflare.com/workers/configuration/routing/custom-domains/).
// So every tunnel name becomes a Custom Domain of one small Worker
// (aegis-tunnels-<label>), which hands each request to this gate through the
// dashboard's own Cloudflare tunnel, saying which name was asked for:
//
//   browser -> radio.tunnel.example.com (Cloudflare, the name's certificate)
//           -> Worker -> https://<dashboard>/... + x-aegis-front-host/-ip/-key
//           -> cloudflared -> Aegis, which serves it as radio.tunnel.example.com
//
// x-aegis-front-key is a random secret only the Worker and this machine know
// (data/cf/front.json), so nothing else can claim a tunnel's name.
//
// Creating Custom Domains needs a Cloudflare credential that may edit
// Workers, which the cloudflared login doesn't give: an API token, or the
// OAuth login of Cloudflare's own CLI, wrangler (refreshed here as it expires).

import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { createServer } from "node:http";

const API = "https://api.cloudflare.com/client/v4";
const WRANGLER_CLIENT = "54d11594-84e4-41aa-b438-e81b8fa78ee7";     // wrangler's public OAuth client
const COMPAT = "2026-01-01";
const REDIRECT = "http://localhost:8976/oauth/callback";                 // the one wrangler's client allows
// what Burrow needs: deploy one Worker and give it Custom Domains (and stay logged in)
const SCOPES = ["account:read", "user:read", "workers:write", "workers_scripts:write", "workers_routes:write", "zone:read", "offline_access"];
const PAGE = (title, text) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title>
<body style="margin:0;display:grid;place-items:center;min-height:100vh;background:#121110;color:#ece6da;font:16px system-ui,sans-serif">
<div style="text-align:center;max-width:420px;padding:24px"><h1 style="font-weight:600;font-size:22px">${title}</h1><p style="color:#a49d92">${text}</p></div>`;

export const WORKER_SOURCE = `// Aegis × Burrow: tunnel names on Cloudflare, handed to the gate through its tunnel.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    headers.set("x-aegis-front-host", url.hostname);
    headers.set("x-aegis-front-ip", request.headers.get("cf-connecting-ip") || "");
    headers.set("x-aegis-front-key", env.KEY);
    return fetch(new URL(url.pathname + url.search, "https://" + env.ORIGIN), {
      method: request.method, headers, body: request.body, redirect: "manual",
    });
  },
};
`;

export class WorkerFront {
  // file: where the credential and the Worker's secret live (mode 600)
  constructor({ file, log, accountId, zoneId }) {
    this.file = file;
    this.log = log || console.log;
    this.accountId = accountId || null;
    this.zoneId = zoneId || null;
    this.state = {};
    try { this.state = JSON.parse(readFileSync(file, "utf8")); } catch { /* not set up */ }
    if (!this.state.key) { this.state.key = randomBytes(32).toString("base64url"); this.save(); }
    this.deployed = null;        // {script, origin} once the Worker is up
    this.error = null;
  }
  save() {
    mkdirSync(dirname(this.file), { recursive: true });
    writeFileSync(this.file + ".tmp", JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(this.file + ".tmp", this.file);
  }
  get linked() { return !!(this.state.token || this.state.oauth?.refresh); }
  // An API token (Workers Scripts: Edit + Workers Routes: Edit), or wrangler's
  // OAuth login ({oauth_token, refresh_token, expiration_time} from its config).
  setCredential({ token, oauth }) {
    if (token) this.state = { ...this.state, token: String(token).trim(), oauth: null };
    else if (oauth?.refresh_token) this.state = { ...this.state, token: null,
      oauth: { access: oauth.oauth_token || null, refresh: oauth.refresh_token, expires: Date.parse(oauth.expiration_time || 0) || 0 } };
    else throw new Error("Give an API token or a wrangler login.");
    this.save();
  }
  async bearer() {
    if (this.state.token) return this.state.token;
    const o = this.state.oauth;
    if (!o?.refresh) throw new Error("No Cloudflare credential for Workers yet.");
    if (o.access && o.expires - Date.now() > 120e3) return o.access;
    const r = await fetch("https://dash.cloudflare.com/oauth2/token", {
      method: "POST", signal: AbortSignal.timeout(20000),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: o.refresh, client_id: WRANGLER_CLIENT }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) throw new Error(`Cloudflare didn't renew the Workers login (${j.error_description || j.error || r.status}); log in again.`);
    this.state.oauth = { access: j.access_token, refresh: j.refresh_token || o.refresh, expires: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
    this.save();
    return j.access_token;
  }
  async api(method, path, body, { form } = {}) {
    const headers = { Authorization: `Bearer ${await this.bearer()}` };
    if (body && !form) headers["Content-Type"] = "application/json";
    const r = await fetch(API + path, { method, headers, body: form || (body ? JSON.stringify(body) : undefined), signal: AbortSignal.timeout(30000) });
    const text = await r.text();
    if (r.ok && !text.trim()) return null;               // a DELETE answers with nothing
    let j = {};
    try { j = JSON.parse(text); } catch { /* not JSON */ }
    if (!j.success) throw new Error((j.errors || []).map((e) => e.message).join("; ") || `HTTP ${r.status}`);
    return j.result;
  }

  // ------------------------------------------------------------ the login, from the dashboard
  // Cloudflare's own OAuth for wrangler (PKCE). Its redirect is fixed to
  // http://localhost:8976/oauth/callback: when the browser runs on this
  // machine, the listener below catches it by itself; otherwise that tab
  // ends on a page that can't load, and its address is pasted back
  // (finishLogin takes the whole address, or just its query).
  startLogin(onDone) {
    this.cancelLogin();
    const verifier = randomBytes(32).toString("base64url");
    const state = randomBytes(18).toString("base64url");
    const url = "https://dash.cloudflare.com/oauth2/auth?" + new URLSearchParams({
      response_type: "code", client_id: WRANGLER_CLIENT, redirect_uri: REDIRECT, scope: SCOPES.join(" "), state,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
    });
    const login = { verifier, state, url, status: "waiting", error: null, started: Date.now(), onDone };
    this.login = login;
    const srv = createServer((req, res) => {
      const u = new URL(req.url || "/", "http://localhost");
      if (u.pathname !== "/oauth/callback") { res.writeHead(404); return res.end(); }
      this.finishLogin(u.search).then(
        () => { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(PAGE("Cloudflare is connected", "Aegis × Burrow is setting up your tunnel names. You can close this tab.")); },
        (e) => { res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" }); res.end(PAGE("That didn't work", String(e.message).replace(/[<&>]/g, ""))); });
    });
    srv.on("error", () => { /* 8976 busy (wrangler itself?): pasting the address still works */ });
    srv.listen(8976, "127.0.0.1");
    login.server = srv;
    login.timer = setTimeout(() => { if (this.login === login && login.status === "waiting") { login.status = "expired"; this.cancelLogin(true); } }, 15 * 60e3);
    login.timer.unref?.();
    return { url, status: login.status };
  }
  cancelLogin(keep) {
    const l = this.login;
    if (!l) return;
    clearTimeout(l.timer);
    try { l.server?.close(); } catch { /* closed */ }
    l.server = null;
    if (!keep) this.login = null;
  }
  loginView() {
    const l = this.login;
    return l ? { status: l.status, error: l.error, url: l.status === "waiting" ? l.url : null } : { status: "none" };
  }
  async finishLogin(pasted) {
    const l = this.login;
    if (!l || l.status !== "waiting") throw new Error("There is no Cloudflare login waiting; start again.");
    const raw = String(pasted || "").trim();
    const q = new URLSearchParams(raw.includes("?") ? raw.slice(raw.indexOf("?") + 1) : raw);
    if (q.get("error")) { l.status = "error"; l.error = q.get("error_description") || q.get("error"); this.cancelLogin(true); throw new Error(`Cloudflare said: ${l.error}`); }
    const code = q.get("code");
    if (!code) throw new Error("That address has no code in it: paste the whole address the Cloudflare tab ended on.");
    if (q.get("state") !== l.state) throw new Error("That address belongs to another login; start again.");
    l.status = "exchanging";
    try {
      const r = await fetch("https://dash.cloudflare.com/oauth2/token", {
        method: "POST", signal: AbortSignal.timeout(20000), headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: WRANGLER_CLIENT, redirect_uri: REDIRECT, code_verifier: l.verifier }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.access_token || !j.refresh_token) throw new Error(j.error_description || j.error || `HTTP ${r.status}`);
      this.state = { ...this.state, token: null, oauth: { access: j.access_token, refresh: j.refresh_token, expires: Date.now() + (Number(j.expires_in) || 3600) * 1000 } };
      this.save();
      this.log("front: Cloudflare Workers connected");
    } catch (e) {
      l.status = "error"; l.error = `Cloudflare didn't accept the login (${e.message})`; this.cancelLogin(true);
      throw new Error(l.error);
    }
    this.cancelLogin(true);
    l.status = "setting-up";
    try { await l.onDone?.(); l.status = "done"; }
    catch (e) { l.status = "error"; l.error = e.message; throw e; }
  }

  scriptName(label) { return `aegis-tunnels-${label}`.slice(0, 63); }
  // Upload the Worker (again, when the dashboard's name changed).
  async deploy(label, origin) {
    const script = this.scriptName(label);
    if (this.deployed?.script === script && this.deployed.origin === origin) return this.deployed;
    const meta = { main_module: "worker.mjs", compatibility_date: COMPAT,
                   bindings: [{ type: "plain_text", name: "ORIGIN", text: origin }, { type: "secret_text", name: "KEY", text: this.state.key }] };
    const form = new FormData();
    form.append("metadata", new Blob([JSON.stringify(meta)], { type: "application/json" }));
    form.append("worker.mjs", new Blob([WORKER_SOURCE], { type: "application/javascript+module" }), "worker.mjs");
    await this.api("PUT", `/accounts/${this.accountId}/workers/scripts/${script}`, null, { form });
    this.deployed = { script, origin };
    this.log(`front: Worker ${script} deployed (to ${origin})`);
    return this.deployed;
  }
  async domains() { return this.api("GET", `/accounts/${this.accountId}/workers/domains?zone_id=${this.zoneId}`); }
  // A tunnel name of its own: a Custom Domain of the Worker (Cloudflare makes the DNS record and the certificate).
  async addDomain(hostname, script) {
    const have = (await this.domains()).find((d) => d.hostname === hostname);
    if (have && have.service === script) return have;
    return this.api("PUT", `/accounts/${this.accountId}/workers/domains`, { environment: "production", hostname, service: script, zone_id: this.zoneId });
  }
  async removeDomain(hostname) {
    const have = (await this.domains()).filter((d) => d.hostname === hostname && d.service?.startsWith("aegis-tunnels-"));
    for (const d of have) await this.api("DELETE", `/accounts/${this.accountId}/workers/domains/${d.id}`);
    return have.length;
  }
  // Is the name's certificate out on Cloudflare's edge yet? A valid
  // handshake, and Cloudflare answering (a cf-ray): an older record of the
  // same name may still point elsewhere for a while.
  async certReady(hostname) {
    try {
      const r = await fetch(`https://${hostname}/`, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(10000) });
      return !!r.headers.get("cf-ray");
    } catch { return false; }
  }

  // Aegis: a request the Worker handed over? -> {host, ip} (and the headers are gone), or null.
  claim(req, fromThisMachine) {
    const key = req.headers["x-aegis-front-key"];
    if (key === undefined) return null;
    const host = String(req.headers["x-aegis-front-host"] || "").toLowerCase();
    const ip = String(req.headers["x-aegis-front-ip"] || "");
    for (const k of ["x-aegis-front-key", "x-aegis-front-host", "x-aegis-front-ip"]) delete req.headers[k];
    const a = Buffer.from(String(key)), b = Buffer.from(this.state.key);
    if (!fromThisMachine || a.length !== b.length || !timingSafeEqual(a, b) || !host) return null;
    return { host, ip };
  }
}
