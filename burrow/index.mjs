// Burrow: the tunnel engine of Aegis × Burrow.
//
// Burrow gives any port on this machine (or the LAN) its own HTTPS address,
// through Cloudflare: tunnel-PORT-<label>.<zone> once a domain is linked, or a
// random *.trycloudflare.com name before. It counts everything that goes
// through, and serves one tunnel API in two places:
//
//   the dashboard   /__gate/api/tunnels…   behind Aegis's login (aegis/server.mjs)
//   the control     data/control.sock      plain HTTP over a Unix socket, mode 600,
//     socket                                for programs of the same user: Selkies
//                                           Forge, bin/burrow
//
// Burrow has no login and no pages of its own. Aegis, in front of it, decides
// who reaches a tunnel (a tunnel is login-protected unless it is public) and
// draws the UI. Burrow can be switched off (state.json modules.burrow): its
// tunnels are kept, but no address answers and no quick tunnel runs.
//
// The tunnel API (paths relative to /__gate/api on the dashboard):
//
//   GET    /tunnels                  {mode, pattern, tunnels: [summary…]}
//   POST   /tunnels                  {port, targetHost?, targetPort?, name?, sub?, access?, password?, scheme?} -> summary
//                                     or {site, sub, name?, access?, password?}: a GitHub/GitLab
//                                     Pages site behind a password (experimental.sites)
//   GET    /tunnels/PORT             details: stats, charts, clients, recent requests
//   PATCH  /tunnels/PORT             any of {name, sub, access, password, enabled, targetHost, targetPort, scheme, site}
//
// access is "login" (the Aegis login, the default), "password" (its own
// password; Burrow keeps only a scrypt hash) or "public".
//   DELETE /tunnels/PORT
//   POST   /tunnels/PORT/kick        {ip?}: drop live connections (one client, or all)
//   GET    /tunnels/PORT/favicon     the target's icon
//   GET    /ports                    listening ports worth publishing
//
// The control socket adds GET /status and POST /module {burrow: bool}, and
// remembers who called (an X-Burrow-Client header, e.g. "selkies-forge/1.10.8")
// so the dashboard can show which apps use Burrow and what they did.

import { createServer } from "node:http";
import { chmodSync, mkdirSync, symlinkSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { TunnelManager } from "./tunnels.mjs";
import { Cloudflare, QuickTunnels, findCloudflared } from "./cloudflare.mjs";

const ACTIVITY = 60;

export class Burrow {
  // settings: get(key) / set(patch), backed by state.json
  // origin:   () => {url, insecure}: where cloudflared reaches the dashboard
  constructor({ settings, dataDir, home, origin, forbiddenPorts, log, version }) {
    this.settings = settings;
    this.log = log || console.log;
    this.version = version;
    this.quick = new QuickTunnels({ bin: () => findCloudflared(settings.get("cloudflared"), home), origin, log: this.log, dataDir });
    this.tunnels = new TunnelManager({ dataDir, domain: settings.get("domain"), quick: this.quick, forbiddenPorts, log: this.log });
    if (!this.on) this.quick.stopAll();
    this.cloudflare = new Cloudflare({
      settings, dataDir, home, origin, log: this.log,
      onDomain: async (domain, phase) => {
        if (phase === "unlinking") await this.tunnels.unpublishAll();
        else { this.tunnels.useDomain(domain); if (domain) await this.tunnels.publishAll(); }
      },
    });
    this.clients = new Map();     // "selkies-forge" -> {name, version, first, last, calls}
    this.activity = [];           // newest first: {at, client, action, port, name}
    this.control = null;
  }

  get on() { return (this.settings.get("modules") || {}).burrow !== false; }

  setOn(on) {
    const was = this.on;
    this.settings.set({ modules: { ...(this.settings.get("modules") || {}), burrow: !!on } });
    if (!on) this.quick.stopAll();
    else if (!was) this.tunnels.useDomain(this.settings.get("domain"));
    if (was !== !!on) this.log("burrow:", on ? "on" : "off");
  }

  // The tunnel a request's Host names, or null (also null while Burrow is off).
  matchHost(host) { return this.on ? this.tunnels.matchHost(host) : null; }

  status() {
    const t = this.tunnels.list();
    return { engine: "burrow", version: this.version, on: this.on, mode: this.tunnels.mode, pattern: this.tunnels.pattern(),
             tunnels: t.length, enabled: t.filter((x) => x.enabled).length,
             mainHost: this.settings.get("domain")?.mainHost || null, cloudflared: !!this.cloudflare.bin() };
  }

  // The tunnel API. Returns {status, json} or {status, body, headers}, or
  // null when the path isn't Burrow's.
  async handle(method, path, readJson) {
    const ok = (json) => ({ status: 200, json });
    if (path !== "/ports" && !path.startsWith("/tunnels")) return null;
    if (!this.on) return { status: 409, json: { error: "Burrow is switched off. Turn it on under Settings → Modules." } };
    const T = this.tunnels;
    if (path === "/tunnels" && method === "GET") return ok({ tunnels: T.list(), now: Date.now(), mode: T.mode, pattern: T.pattern() });
    if (path === "/tunnels" && method === "POST") {
      const spec = await readJson();
      if (spec.site && !(this.settings.get("experimental") || {}).sites) {
        return { status: 409, json: { error: "Secure reverse tunneling is experimental: switch it on under Settings → Experimental first." } };
      }
      return ok(await T.create(spec));
    }
    if (path === "/ports" && method === "GET") return ok({ ports: await T.ports() });
    const m = /^\/tunnels\/(\d{1,5})(\/favicon|\/kick)?$/.exec(path);
    if (!m) return null;
    const port = Number(m[1]);
    if (m[2] === "/favicon") {
      const f = T.favicon(port);
      if (!f) return { status: 404, body: "" };
      return { status: 200, body: f.body, headers: { "Content-Type": f.type, "Cache-Control": "private, max-age=86400",
                                                     "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" } };
    }
    if (m[2] === "/kick" && method === "POST") return ok({ kicked: T.kick(port, (await readJson()).ip || null) });
    if (m[2]) return null;
    if (method === "GET") { const d = T.details(port); return d ? ok(d) : { status: 404, json: { error: "No such tunnel." } }; }
    if (method === "PATCH") return ok(await T.update(port, await readJson()));
    if (method === "DELETE") return ok(await T.remove(port));
    return null;
  }

  // ------------------------------------------------------------ control socket
  note(client, action, port, name) {
    this.activity.unshift({ at: Date.now(), client, action, port: port || null, name: name || null });
    this.activity.length = Math.min(this.activity.length, ACTIVITY);
  }

  // extra(method, path, readJson) -> {status, json} | null: routes the dashboard adds
  listenControl(path, extra) {
    const readJson = (req) => new Promise((resolve, reject) => {
      let size = 0; const chunks = [];
      req.on("data", (c) => { size += c.length; if (size > 65536) { reject(new Error("too large")); req.destroy(); } else chunks.push(c); });
      req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch { reject(new Error("bad JSON")); } });
      req.on("error", reject);
    });
    this.control = createServer(async (req, res) => {
      const reply = (status, obj, headers = {}) => {
        res.writeHead(status, { "Content-Type": "application/json", ...headers });
        res.end(Buffer.isBuffer(obj) || typeof obj === "string" ? obj : JSON.stringify(obj));
      };
      // who is calling: "selkies-forge/1.10.8", or "local" for a bare request
      const [cid, cver] = String(req.headers["x-burrow-client"] || "local").slice(0, 80).split("/");
      const id = /^[a-z0-9][a-z0-9._-]{0,39}$/i.test(cid) ? cid.toLowerCase() : "local";
      const c = this.clients.get(id) || { id, version: null, first: Date.now(), calls: 0 };
      Object.assign(c, { version: cver || c.version, last: Date.now(), calls: c.calls + 1 });
      this.clients.set(id, c);
      try {
        const path = new URL(req.url || "/", "http://x").pathname.replace(/^\/__gate\/api/, "");
        if (path === "/status" && req.method === "GET") return reply(200, this.status());
        const x = extra ? await extra(req.method, path, () => readJson(req)) : null;
        if (x) { if (req.method !== "GET") this.note(id, `changed ${path.slice(1)}`); return reply(x.status, x.json); }
        if (path === "/module" && req.method === "POST") {
          const b = await readJson(req);
          this.setOn(b.burrow !== false);
          this.note(id, this.on ? "switched Burrow on" : "switched Burrow off");
          return reply(200, this.status());
        }
        const before = req.method === "DELETE" || req.method === "PATCH" ? this.tunnels.get(Number(path.split("/")[2])) : null;
        const r = await this.handle(req.method, path, () => readJson(req));
        if (!r) return reply(404, { error: "not found" });
        if (r.status === 200 && req.method !== "GET") {
          const t = r.json || {};
          const port = t.port || before?.port, name = t.name || before?.name;
          const what = req.method === "POST" ? (path.endsWith("/kick") ? "kicked clients from" : "published")
                     : req.method === "DELETE" ? "unpublished" : "changed";
          this.note(id, what, port, name);
          this.log(`control: ${id} ${what} ${port || ""} ${name || ""}`.trim());
        }
        if (path === "/tunnels" && req.method === "GET" && r.status === 200) {
          r.json = { app: "aegis-burrow", engine: "burrow", version: this.version, mainHost: this.settings.get("domain")?.mainHost || null, ...r.json };
        }
        return r.body !== undefined ? reply(r.status, r.body, r.headers) : reply(r.status, r.json);
      } catch (e) { return reply(400, { error: e.message }); }
    });
    // A socket path can't be longer than ~107 bytes. Deep homes get a short
    // one in a private runtime folder, and data/control.sock links to it.
    let real = path;
    if (Buffer.byteLength(path) > 100) {
      const dir = join(process.env.XDG_RUNTIME_DIR || tmpdir(), `burrow-${process.getuid()}`);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
      real = join(dir, createHash("sha256").update(path).digest("hex").slice(0, 16) + ".sock");
    }
    for (const p of new Set([path, real])) { try { unlinkSync(p); } catch { /* none */ } }
    this.control.on("error", (e) => this.log("control socket:", e.message));
    this.control.listen(real, () => {
      try { chmodSync(real, 0o600); } catch { /* best effort */ }
      if (real !== path) { try { symlinkSync(real, path); } catch (e) { this.log("control socket link:", e.message); } }
    });
    this.controlPath = path;
    this.controlReal = real;
  }

  // For the dashboard: which programs used the control socket, and what they did.
  controlView() {
    return { path: this.controlPath || null, clients: [...this.clients.values()].sort((a, b) => b.last - a.last),
             activity: this.activity.slice(0, 30) };
  }

  stop() {
    this.tunnels.stop(); this.cloudflare.stop();
    for (const p of new Set([this.controlPath, this.controlReal].filter(Boolean))) { try { unlinkSync(p); } catch { /* gone */ } }
  }
}
