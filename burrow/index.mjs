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
//                                     Pages site behind a password (needs the Burrow Pages addon)
//   GET    /tunnels/PORT             details: stats, charts, clients, recent requests
//   PATCH  /tunnels/PORT             any of {name, sub, access, password, enabled, targetHost, targetPort, scheme, site}
//
// access is "login" (the Aegis login, the default), "password" (its own
// password; Burrow keeps only a scrypt hash) or "public".
//   DELETE /tunnels/PORT
//   POST   /tunnels/PORT/kick        {ip?}: drop live connections (one client, or all)
//   GET    /tunnels/PORT/favicon     the target's icon
//   GET    /ports                    listening ports worth publishing
//   GET    /ipintel/IP               an address's reputation (ipintel.mjs), in under half a second
//   GET    /shield                   the shield (shield.mjs): bans, lists, what it turned away
//   PUT    /shield                   {auto?, drop?, lookups?}
//   POST   /shield/ban               {ip, reason?}     POST /shield/unban {ip}
//   POST   /shield/allow             {ip, note?}       POST /shield/disallow {ip}
//   POST   /shield/feeds             download every list again now
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
import { checkIp, checkMany, useLists } from "./ipintel.mjs";
import { Shield } from "./shield.mjs";

const ACTIVITY = 60;

export class Burrow {
  // settings: get(key) / set(patch), backed by state.json
  // origin:   () => {url, insecure}: where cloudflared reaches the dashboard
  // edge:     {port, upnp}: where wildcard tunnels answer on this machine's own certificate (edge.mjs)
  constructor({ settings, dataDir, home, origin, forbiddenPorts, log, version, edge }) {
    this.settings = settings;
    this.log = log || console.log;
    this.version = version;
    this.quick = new QuickTunnels({ bin: () => findCloudflared(settings.get("cloudflared"), home), origin, log: this.log, dataDir });
    this.tunnels = new TunnelManager({ dataDir, domain: settings.get("domain"), quick: this.quick, forbiddenPorts, log: this.log,
                                       naming: settings.get("tunnelNaming"), edge,
                                       onNaming: ({ mode, prefix, certs, relay }) => settings.set({ tunnelNaming: { mode, prefix, certs, relay } }) });
    if (!this.on) this.quick.stopAll();
    this.cloudflare = new Cloudflare({
      settings, dataDir, home, origin, log: this.log,
      onDomain: async (domain, phase) => {
        if (phase === "unlinking") await this.tunnels.unpublishAll();
        else { this.tunnels.useDomain(domain); if (domain) await this.tunnels.publishAll(); }
      },
    });
    // who may reach the gate at all (shield.mjs); Aegis asks it about every request
    this.shield = new Shield({
      dataDir, log: this.log,
      remote: (ip, { probe }) => checkIp(ip, { light: true, probe, deadline: 0 }),
      onBan: (ip) => { for (const port of this.tunnels.tunnels.keys()) this.tunnels.kick(port, ip); },
    });
    useLists((ip) => this.shield.lookup(ip), (ip) => (this.shield.lists.has("tor") ? this.shield.lookup(ip).some((l) => l.id === "tor") : null));
    this.clients = new Map();     // "selkies-forge" -> {name, version, first, last, calls}
    this.activity = [];           // newest first: {at, client, action, port, name}
    this.control = null;
    // Sites (GitHub/GitLab Pages behind a password) come with the Burrow Pages
    // addon (github.com/alexd-aero/burrow-pages); Aegis says whether it is installed.
    this.sitesAllowed = () => false;
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
    // an IP's reputation (ipintel.mjs): GET /ipintel/<ip>
    const ipm = /^\/ipintel\/([0-9a-fA-F.:]{3,45})$/.exec(path);
    if (ipm && method === "GET") {
      try { return ok({ ...(await checkIp(ipm[1])), shield: this.shield.peek(ipm[1]) }); } catch (e) { return { status: 400, json: { error: e.message } }; }
    }
    if (path === "/shield" || path.startsWith("/shield/")) return this.shieldRoute(method, path, readJson);
    if (path !== "/ports" && !path.startsWith("/tunnels")) return null;
    if (!this.on) return { status: 409, json: { error: "Burrow is switched off. Turn it on under Settings → Modules." } };
    const T = this.tunnels;
    if (path === "/tunnels" && method === "GET") return ok({ tunnels: T.list(), now: Date.now(), mode: T.mode, pattern: T.pattern() });
    if (path === "/tunnels" && method === "POST") {
      const spec = await readJson();
      if (spec.site && !this.sitesAllowed()) {
        return { status: 409, json: { error: "Sites come with the Burrow Pages addon: install it under Burrow → Addons." } };
      }
      return ok(await T.create(spec));
    }
    if (path === "/ports" && method === "GET") return ok({ ports: await T.ports() });
    // a DNS record per tunnel, or one wildcard *.<prefix>.<zone> for all of them
    if (path === "/tunnels/naming" && method === "GET") return ok(T.namingInfo());
    // The Worker front's login, from the dashboard: start it with the naming the
    // user picked; once Cloudflare says yes, that naming is applied by itself.
    //   POST /tunnels/front/login {naming?} -> {url, status}
    //   GET  /tunnels/front/login           -> {status: waiting|exchanging|setting-up|done|error|expired, error, naming}
    //   POST /tunnels/front/login/finish {url}: the address the Cloudflare tab ended on
    if (path === "/tunnels/front/login" && method === "POST") {
      const b = await readJson();
      const want = b.naming ? { ...b.naming, certs: "worker" } : null;
      return ok(T.front.startLogin(async () => {
        if (want) await T.setNaming(want);
        else if (T.frontMode) await T.publishAll();
      }));
    }
    if (path === "/tunnels/front/login" && method === "GET") return ok({ ...T.front.loginView(), naming: T.namingInfo() });
    if (path === "/tunnels/front/login/finish" && method === "POST") {
      try { await T.front.finishLogin((await readJson()).url); return ok({ ...T.front.loginView(), naming: T.namingInfo() }); }
      catch (e) { return { status: 400, json: { error: e.message, ...T.front.loginView() } }; }
    }
    // the Worker front's Cloudflare credential: {token} (Workers Scripts + Routes: Edit), or {wrangler: "<its config file>"}
    if (path === "/tunnels/front" && method === "PUT") {
      const b = await readJson();
      try {
        if (b.wrangler) {
          const val = (k) => String(b.wrangler).split("\n").find((l) => l.startsWith(k + " = "))?.slice(k.length + 3).trim().replace(/^"|"$/g, "");
          T.front.setCredential({ oauth: { oauth_token: val("oauth_token"), refresh_token: val("refresh_token"), expiration_time: val("expiration_time") } });
        } else T.front.setCredential({ token: b.token });
        await T.front.bearer();
        return ok(T.namingInfo());
      } catch (e) { return { status: 400, json: { error: e.message } }; }
    }
    if (path === "/tunnels/naming" && method === "PUT") {
      const body = await readJson();
      try {
        return ok(await T.setNaming(body, { force: !!body.force }));      // kept through onNaming (relay and certs too)
      } catch (e) {
        return { status: 400, json: { error: e.message, code: e.code || null } };
      }
    }
    const m = /^\/tunnels\/(\d{1,5})(\/favicon|\/kick|\/scan)?$/.exec(path);
    if (!m) return null;
    const port = Number(m[1]);
    if (m[2] === "/favicon") {
      const f = T.favicon(port);
      if (!f) return { status: 404, body: "" };
      return { status: 200, body: f.body, headers: { "Content-Type": f.type, "Cache-Control": "private, max-age=86400",
                                                     "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" } };
    }
    if (m[2] === "/kick" && method === "POST") return ok({ kicked: T.kick(port, (await readJson()).ip || null) });
    // every client of the tunnel through the IP checks (the most recent first)
    if (m[2] === "/scan" && method === "POST") {
      const d = T.details(port);
      if (!d) return { status: 404, json: { error: "No such tunnel." } };
      return ok({ results: await checkMany([...d.clientList].sort((a, b) => (b.last || 0) - (a.last || 0)).map((c) => c.ip)) });
    }
    if (m[2]) return null;
    if (method === "GET") {
      const d = T.details(port);
      if (d) for (const c of d.clientList) c.shield = this.shield.peek(c.ip);
      return d ? ok(d) : { status: 404, json: { error: "No such tunnel." } };
    }
    if (method === "PATCH") return ok(await T.update(port, await readJson()));
    if (method === "DELETE") return ok(await T.remove(port));
    return null;
  }

  async shieldRoute(method, path, readJson) {
    const ok = (json) => ({ status: 200, json });
    const S = this.shield;
    try {
      if (path === "/shield" && method === "GET") return ok(S.view());
      if (path === "/shield" && method === "PUT") { S.setSettings(await readJson()); return ok(S.view()); }
      if (method !== "POST") return null;
      if (path === "/shield/feeds") { await S.refreshDue(true); return ok(S.view()); }
      const b = await readJson();
      if (path === "/shield/ban") { S.ban(b.ip, b.reason || "banned by you", { source: "manual" }); return ok(S.view()); }
      if (path === "/shield/unban") { S.unban(b.ip); return ok(S.view()); }
      if (path === "/shield/allow") { S.allow(b.ip, true, b.note || ""); return ok(S.view()); }
      if (path === "/shield/disallow") { S.allow(b.ip, false); return ok(S.view()); }
    } catch (e) { return { status: 400, json: { error: e.message } }; }
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
    this.tunnels.stop(); this.cloudflare.stop(); this.shield.stop();
    for (const p of new Set([this.controlPath, this.controlReal].filter(Boolean))) { try { unlinkSync(p); } catch { /* gone */ } }
  }
}
