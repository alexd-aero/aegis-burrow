// Burrow, the engine: more domains.
//
// The first domain (cloudflare.mjs, Settings → Domain) is the main one: the
// dashboard's own name, sign-ins, and the tunnels' naming (a record each, or
// the wildcard through your VPS, a Worker…). Any number of other Cloudflare
// domains can be added beside it, each one on its own:
//
//   its own authorization   `cloudflared tunnel login` again, picking the other
//                           zone; the cert.pem is kept in data/cf/domains/<zone>/
//   its own tunnel          a named Cloudflare tunnel, and a cloudflared that
//                           Aegis runs for it (like the main one's), so it
//                           works whatever routes the main domain, even across
//                           Cloudflare accounts
//   two records at most     <label>.<zone> for the dashboard (no label: none),
//                           and *.<zone> for the tunnels (unless "none")
//
// Tunnels on another domain are https://<name>.<zone>: the tunnel's own name
// (t.sub) or its port, one level under the zone, so Cloudflare's free
// certificate covers them and nothing is added per tunnel. Which tunnels
// answer there is the domain's `tunnels`:
//   "all"     every tunnel
//   "picked"  only tunnels that list the zone (t.domains, set on the tunnel)
//   "none"    the dashboard only; no wildcard record
// A tunnel still has its access (login, password, public) on every name, and
// signs in through the main dashboard, so one sign-in covers every domain.
//
// settings "domains": [{zone: {id, name}, label, tunnels, tunnelId, tunnelName,
//                       cert, creds, linked}]

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { LOGIN_URL_RE, LABEL_RE, Supervised, decodeCert, cfApi as realCfApi, run as realRun } from "./cloudflare.mjs";

const MODES = new Set(["all", "picked", "none"]);
const COMMENT = "aegis: another domain";
const ZONE_RE = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const TAKEN_TTL = 15 * 60e3;

export class Domains {
  // bin: () => cloudflared's path or null; mainZone: () => the main domain's zone name or null
  // onChange: (list) => void, after anything that changes which names answer
  // cfApi / run: Cloudflare's API and cloudflared, replaceable in tests
  constructor({ settings, dataDir, origin, log, bin, mainZone, onChange, cfApi = realCfApi, run = realRun, autostart = true }) {
    this.settings = settings;
    this.dir = join(dataDir, "cf", "domains");
    this.home = join(this.dir, "home");
    this.origin = origin;
    this.log = log || console.log;
    this.bin = bin;
    this.mainZone = mainZone;
    this.onChange = onChange;
    this.cfApi = cfApi;
    this.run = run;
    this.login = null;
    this.connectors = new Map();       // zone name -> Supervised
    this.taken = new Map();            // zone name -> {at, names: Set} records that aren't ours (they win over the wildcard)
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (autostart) for (const d of this.list()) this.startConnector(d);
  }

  list() { return (this.settings.get("domains") || []).filter((d) => d?.zone?.name && d.tunnelId); }
  get(zone) { return this.list().find((d) => d.zone.name === String(zone || "").toLowerCase()) || null; }
  save(list) { this.settings.set({ domains: list }); this.onChange?.(list); }
  pendingPath() { return join(this.dir, "pending.pem"); }
  pending() { return existsSync(this.pendingPath()) ? this.settings.get("domainsPending") || null : null; }
  target(d) { return `${d.tunnelId}.cfargotunnel.com`; }
  dashboardOf(d) { return d.label ? `${d.label}.${d.zone.name}` : null; }

  // ------------------------------------------------------------- names
  isDashboard(host) {
    const name = String(host || "").toLowerCase().split(":")[0];
    return this.list().some((d) => d.label && name === this.dashboardOf(d));
  }
  // Names on a zone that have a record of their own (not ours): they never reach the wildcard.
  takenOn(zone) { return this.taken.get(zone)?.names || new Set(); }
  async refreshTaken(d, force = false) {
    const t = this.taken.get(d.zone.name);
    if (!force && t && Date.now() - t.at < TAKEN_TTL) return;
    this.taken.set(d.zone.name, { at: Date.now(), names: t?.names || new Set() });          // one refresh at a time
    try {
      const c = decodeCert(d.cert);
      const recs = await this.cfApi(c.token, "GET", `/zones/${c.zoneId}/dns_records?per_page=1000`);
      const names = new Set(recs.filter((r) => r.content !== this.target(d) && !r.name.startsWith("*.")).map((r) => r.name.toLowerCase()));
      this.taken.set(d.zone.name, { at: Date.now(), names });
    } catch (e) { this.log("domains: could not read", d.zone.name, "records:", e.message); }
  }

  view() {
    for (const d of this.list()) this.refreshTaken(d).then(() => {}, () => {});
    const p = this.pending();
    return {
      cloudflared: !!this.bin(),
      main: this.mainZone() || null,
      domains: this.list().map((d) => {
        const c = this.connectors.get(d.zone.name);
        return { zone: d.zone.name, label: d.label || "", dashboard: this.dashboardOf(d), tunnels: d.tunnels, linked: d.linked,
                 example: d.tunnels === "none" ? null : `NAME.${d.zone.name}`,
                 connector: { running: !!c?.running, since: c?.since || null, log: (c?.lines || []).slice(-12) } };
      }),
      login: this.login ? { url: this.login.url, error: this.login.error, waiting: !!this.login.proc } : null,
      pending: p ? { zone: p.name || null } : null,
    };
  }

  // ------------------------------------------------------------- authorization
  // `cloudflared tunnel login` with a HOME of its own; the cert it receives waits
  // in pending.pem until add() uses it (or forget() drops it).
  startLogin() {
    if (!this.mainZone()) throw new Error("Link the main domain first (above).");
    const bin = this.bin();
    if (!bin) throw new Error("cloudflared is not installed.");
    if (this.login?.proc && this.login.url) return Promise.resolve({ url: this.login.url });
    const got = join(this.home, ".cloudflared", "cert.pem");
    rmSync(got, { force: true });
    mkdirSync(join(this.home, ".cloudflared"), { recursive: true, mode: 0o700 });
    const proc = spawn(bin, ["tunnel", "--no-autoupdate", "login"], {
      env: { ...process.env, HOME: this.home, TUNNEL_ORIGIN_CERT: got }, stdio: ["ignore", "pipe", "pipe"],
    });
    const login = { proc, url: null, error: null, out: "" };
    this.login = login;
    return new Promise((resolve, reject) => {
      const feed = (buf) => {
        login.out = (login.out + buf).slice(-4000);
        const m = LOGIN_URL_RE.exec(login.out);
        if (m && !login.url) { login.url = m[0]; resolve({ url: login.url }); }
      };
      proc.stdout.on("data", feed);
      proc.stderr.on("data", feed);
      proc.on("error", (e) => { login.error = e.message; login.proc = null; reject(e); });
      proc.on("exit", async (code) => {
        login.proc = null;
        if (code === 0 && existsSync(got)) {
          try { await this.takeCert(got); } catch (e) { login.error = e.message; rmSync(got, { force: true }); }
        } else if (!login.error) {
          login.error = code === null ? "Cancelled." : (login.out.split("\n").filter((l) => /error|ERR|failed/i.test(l)).pop() || `cloudflared exited with ${code}`).slice(0, 300);
        }
        if (!login.url) reject(new Error(login.error || "cloudflared did not print a login link"));
      });
      setTimeout(() => { if (!login.url) { try { proc.kill(); } catch { /* gone */ } reject(new Error("cloudflared did not print a login link within 30 s")); } }, 30000);
    });
  }
  // A cert from Cloudflare: which zone it is for, and that it's a new one.
  async takeCert(file) {
    const c = decodeCert(file);
    const zone = await this.cfApi(c.token, "GET", `/zones/${c.zoneId}`);
    const name = String(zone?.name || "").toLowerCase();
    if (!ZONE_RE.test(name)) throw new Error("Could not read the domain's name from Cloudflare.");
    if (name === this.mainZone()) throw new Error(`${name} is already the main domain. Pick another domain on the Cloudflare page.`);
    if (this.get(name)) throw new Error(`${name} is already added.`);
    renameSync(file, this.pendingPath());
    this.settings.set({ domainsPending: { id: c.zoneId, name } });
    this.log("domains: authorized for", name);
  }
  cancelLogin() {
    if (this.login?.proc) { try { this.login.proc.kill(); } catch { /* gone */ } }
    this.login = null;
    return this.view();
  }
  forget() {
    rmSync(this.pendingPath(), { force: true });
    this.settings.set({ domainsPending: null });
    this.login = null;
    return this.view();
  }

  // ------------------------------------------------------------- add, change, remove
  static clean({ label, tunnels } = {}) {
    label = String(label ?? "").trim().toLowerCase();
    if (label && !LABEL_RE.test(label)) throw new Error("The dashboard's name is 1-40 letters, digits and dashes (not at the ends), or empty for none.");
    if (/^\d+$/.test(label)) throw new Error("A name of only digits is how tunnels are reached; add a letter.");
    if (tunnels != null && !MODES.has(tunnels)) throw new Error("Tunnels on it: all, picked or none.");
    return { label, tunnels };
  }

  async add(spec) {
    const { label, tunnels = "all" } = Domains.clean(spec);
    const p = this.pending();
    if (!p?.name) throw new Error("Authorize Cloudflare for the other domain first.");
    if (this.get(p.name)) throw new Error(`${p.name} is already added.`);
    if (!label && tunnels === "none") throw new Error("Give it the dashboard, some tunnels, or both.");
    const bin = this.bin();
    if (!bin) throw new Error("cloudflared is not installed.");
    const dir = join(this.dir, p.name);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const cert = join(dir, "cert.pem"), creds = join(dir, "tunnel.json");
    renameSync(this.pendingPath(), cert);
    const giveBack = () => { try { renameSync(cert, this.pendingPath()); } catch { /* gone */ } rmSync(dir, { recursive: true, force: true }); };
    const name = `aegis-${p.name.replace(/\./g, "-").slice(0, 40)}-${randomBytes(3).toString("hex")}`;
    rmSync(creds, { force: true });
    const r = await this.run(bin, ["--origincert", cert, "tunnel", "--no-autoupdate", "create", "--credentials-file", creds, name], { env: { ...process.env, HOME: this.home } });
    const id = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/.exec(r.out + r.err)?.[1];
    if (r.code !== 0 || !id) { giveBack(); throw new Error(`cloudflared could not create the tunnel: ${(r.err || r.out).trim().split("\n").pop()}`); }
    const d = { zone: { id: p.id, name: p.name }, label, tunnels, tunnelId: id, tunnelName: name, cert, creds, linked: Date.now() };
    try { await this.syncRecords(d, null); }
    catch (e) {
      await this.run(bin, ["--origincert", cert, "tunnel", "delete", "-f", id], { env: { ...process.env, HOME: this.home } });
      giveBack();
      throw e;
    }
    this.settings.set({ domainsPending: null });
    this.save([...this.list(), d]);
    this.startConnector(d);
    this.refreshTaken(d, true).then(() => {}, () => {});
    this.log("domains: added", p.name, label ? `(dashboard ${this.dashboardOf(d)})` : "", "tunnels:", tunnels);
    return this.view();
  }

  async update(zone, patch) {
    const d = this.get(zone);
    if (!d) throw new Error("No such domain.");
    const c = Domains.clean({ label: "label" in patch ? patch.label : d.label, tunnels: patch.tunnels ?? d.tunnels });
    if (!c.label && c.tunnels === "none") throw new Error("Give it the dashboard, some tunnels, or both. (Or remove the domain.)");
    const next = { ...d, label: c.label, tunnels: c.tunnels };
    await this.syncRecords(next, d);
    this.save(this.list().map((x) => (x.zone.name === d.zone.name ? next : x)));
    if (next.label !== d.label) this.startConnector(next);
    this.log("domains:", d.zone.name, "now", next.label ? `dashboard ${this.dashboardOf(next)},` : "no dashboard,", "tunnels:", next.tunnels);
    return this.view();
  }

  async remove(zone) {
    const d = this.get(zone);
    if (!d) throw new Error("No such domain.");
    this.connectors.get(d.zone.name)?.stop();
    this.connectors.delete(d.zone.name);
    try { await this.syncRecords({ ...d, label: "", tunnels: "none" }, d); } catch (e) { this.log("domains: could not remove", d.zone.name, "records:", e.message); }
    const bin = this.bin();
    if (bin) {
      const env = { env: { ...process.env, HOME: this.home } };
      await this.run(bin, ["--origincert", d.cert, "tunnel", "cleanup", d.tunnelId], env);
      const r = await this.run(bin, ["--origincert", d.cert, "tunnel", "delete", "-f", d.tunnelId], env);
      if (r.code !== 0) this.log("domains: tunnel delete:", (r.err || r.out).trim().split("\n").pop());
    }
    rmSync(join(this.dir, d.zone.name), { recursive: true, force: true });
    this.taken.delete(d.zone.name);
    this.save(this.list().filter((x) => x.zone.name !== d.zone.name));
    this.log("domains: removed", d.zone.name);
    return this.view();
  }

  // The records `d` needs, made first; then the ones `was` had that `d` doesn't, removed.
  // Never takes over a record that isn't ours (mail, www, a website…).
  async syncRecords(d, was) {
    const c = decodeCert(d.cert), api = (m, p, b) => this.cfApi(c.token, m, `/zones/${c.zoneId}${p}`, b);
    const want = new Set([this.dashboardOf(d), d.tunnels !== "none" ? `*.${d.zone.name}` : null].filter(Boolean));
    const had = new Set(was ? [this.dashboardOf(was), was.tunnels !== "none" ? `*.${was.zone.name}` : null].filter(Boolean) : []);
    const body = (name) => ({ type: "CNAME", name, content: this.target(d), proxied: true, ttl: 1, comment: COMMENT });
    for (const name of want) {
      if (had.has(name)) continue;
      const recs = await api("GET", `/dns_records?name=${encodeURIComponent(name)}`);
      const rec = recs.find((r) => r.name === name);
      if (rec && rec.type === "CNAME" && rec.content === this.target(d)) continue;
      if (rec && rec.comment !== COMMENT) {
        throw new Error(`${name} already has a ${rec.type} record${rec.content ? ` (${rec.content})` : ""}. ${name.startsWith("*.") ? "Delete it on Cloudflare first, or set tunnels to none." : "Pick another name, or none."}`);
      }
      if (rec) await api("PUT", `/dns_records/${rec.id}`, body(name));
      else await api("POST", "/dns_records", body(name));
    }
    for (const name of had) {
      if (want.has(name)) continue;
      const recs = await api("GET", `/dns_records?name=${encodeURIComponent(name)}`);
      for (const r of recs) if (r.type === "CNAME" && r.content === this.target(was)) await api("DELETE", `/dns_records/${r.id}`);
    }
  }

  // ------------------------------------------------------------- connectors
  writeConfig(d) {
    const o = this.origin();
    const req = o.insecure ? "    originRequest:\n      noTLSVerify: true" : "";
    const rule = (host) => [`  - hostname: "${host}"`, `    service: ${o.url}`, req];
    const yml = [
      `# Written by Aegis for ${d.zone.name} (another domain). Changes are overwritten.`,
      `tunnel: ${d.tunnelId}`,
      `credentials-file: ${d.creds}`,
      "protocol: quic",
      "loglevel: info",
      "ingress:",
      ...(d.label ? rule(this.dashboardOf(d)) : []),
      ...rule(`*.${d.zone.name}`),
      "  - service: http_status:404",
    ].filter(Boolean).join("\n") + "\n";
    const file = join(this.dir, d.zone.name, "cloudflared.yml");
    writeFileSync(file, yml, { mode: 0o600 });
    return file;
  }
  startConnector(d) {
    const bin = this.bin();
    if (!bin || !existsSync(d.creds)) return;
    const file = this.writeConfig(d);
    let sup = this.connectors.get(d.zone.name);
    if (sup) sup.stop();
    else { sup = new Supervised(`connector ${d.zone.name}`, this.log); this.connectors.set(d.zone.name, sup); }
    sup.start(bin, ["--no-autoupdate", "--config", file, "tunnel", "--post-quantum", "run"], { HOME: this.home });
  }
  stop() { for (const s of this.connectors.values()) s.stop(); this.cancelLogin(); }
}
