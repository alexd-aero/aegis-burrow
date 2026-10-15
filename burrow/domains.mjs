// Burrow, the engine: more domains.
//
// The first domain (cloudflare.mjs, Settings → Domain) is the main one: the
// dashboard's own name, sign-ins, and the tunnels' naming (a record each, or
// the wildcard through your VPS, a Worker…). Any number of other Cloudflare
// domains can be added beside it, each one on its own.
//
// Access to the domain: Aegis first tries every Cloudflare credential it
// already holds (the main domain's, the other domains', API tokens you gave
// it), so a domain those can reach needs no sign-in at all. Only if none can
// does it ask: `cloudflared tunnel login` (picking that domain), or an API
// token pasted once (one for all your zones makes every later domain free).
// Whatever worked is kept as a cert.pem in data/cf/domains/<zone>/.
//
// On the domain:
//   <label>.<zone>   the dashboard (no label: none), through a Cloudflare
//                    tunnel of the domain's own and a cloudflared Aegis runs
//   *.<zone>         the tunnels (unless "none"), https://<sub|PORT>.<zone>,
//                    one level under the zone, nothing added per tunnel
// Which tunnels answer there is `tunnels`: "all", "picked" (the tunnel lists
// the zone in t.domains) or "none". Where they arrive is `route`:
//   "vps"         your VPS (Aegis Relay, relaylink.mjs): *.<zone> is a plain A
//                 record to it; Aegis gets a Let's Encrypt wildcard for *.<zone>
//                 (DNS-01 with the domain's token), puts it on the VPS's agent
//                 over the signed link, and renews it. No command on the VPS:
//                 the agent takes the new zone as it takes a certificate
//   "cloudflare"  Cloudflare's proxy: *.<zone> is a proxied CNAME to the
//                 domain's tunnel (its free certificate covers one level)
// Subdomains (d.subs), beside those, each one of two kinds:
//   {name, wildcard: true}         *.<name>.<zone>: the same tunnels as `tunnels`
//                                  (all or picked) at https://<sub|PORT>.<name>.<zone>;
//                                  through your VPS only (a certificate of its own,
//                                  pushed to the agent with the suffix .<name>.<zone>),
//                                  since Cloudflare's free certificate covers one level
//   {name, wildcard: false, port}  <name>.<zone>: one tunnel, that one only, a record
//                                  of its own (it wins over *.<zone>)
// A Cloudflare tunnel is only made when something needs it (the dashboard, or
// the "cloudflare" route), so a token that can only edit DNS is enough for a
// domain that sends its tunnels through your VPS.
// A tunnel keeps its access (login, password, public) on every name, and signs
// in through the main dashboard, so one sign-in covers every domain.
//
// settings "domains": [{zone: {id, name}, label, tunnels, route, subs, cert,
//                       tunnelId?, tunnelName?, creds?, linked}]
// settings "cfTokens": [{token, added}]   API tokens you pasted

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isIP } from "node:net";
import { randomBytes } from "node:crypto";
import { LOGIN_URL_RE, LABEL_RE, Supervised, decodeCert, cfApi as realCfApi, run as realRun } from "./cloudflare.mjs";
import { Acme, CertFiles, LETSENCRYPT } from "./acme.mjs";
import { txtVisible as realTxtVisible } from "./edge.mjs";

const MODES = new Set(["all", "picked", "none"]);
const ROUTES = new Set(["vps", "cloudflare"]);
const COMMENT = "aegis: another domain";
export const ZONE_RE = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const TAKEN_TTL = 15 * 60e3;
const MAX_SUBS = 20;
const RENEW_BEFORE_MS = 30 * 864e5;
const RENEW_EVERY_MS = 6 * 3600e3;
const RETRY_MS = 3600e3;

// a cert.pem in cloudflared's format, for credentials that didn't come from cloudflared
export const makeCert = ({ zoneId, accountId, token }) =>
  `-----BEGIN ARGO TUNNEL TOKEN-----\n${Buffer.from(JSON.stringify({ zoneID: zoneId, accountID: accountId, apiToken: token })).toString("base64").replace(/.{1,64}/g, "$&\n")}-----END ARGO TUNNEL TOKEN-----\n`;

export class Domains {
  // bin: () => cloudflared's path or null; mainZone: () => the main domain's zone name or null
  // mainCert: () => the main domain's cert.pem path or null (its token is tried first)
  // onChange: (list) => void, after anything that changes which names answer
  // cfApi / run / acme / txtVisible: Cloudflare, cloudflared, Let's Encrypt, DNS checks (replaceable in tests)
  constructor({ settings, dataDir, origin, log, bin, mainZone, mainCert = () => null, onChange,
                cfApi = realCfApi, run = realRun, acme, txtVisible = realTxtVisible, autostart = true }) {
    this.settings = settings;
    this.dir = join(dataDir, "cf", "domains");
    this.home = join(this.dir, "home");
    this.origin = origin;
    this.log = log || console.log;
    this.bin = bin;
    this.mainZone = mainZone;
    this.mainCert = mainCert;
    this.onChange = onChange;
    this.cfApi = cfApi;
    this.run = run;
    this.txtVisible = txtVisible;
    this.files = new CertFiles(join(dataDir, "certs"));
    this.acme = acme || new Acme({ dir: join(dataDir, "certs"), directory: process.env.AEGIS_ACME_DIRECTORY || LETSENCRYPT, log: this.log });
    this.relay = null;                 // useRelay(): your VPS, through Aegis Relay
    this.login = null;
    this.need = null;                  // {zone, error?}: none of Aegis's credentials reach it
    this.connectors = new Map();       // zone name -> Supervised
    this.taken = new Map();            // zone name -> {at, names: Set} records that aren't ours (they win over the wildcard)
    this.certState = new Map();        // zone name -> {issuing, error, retryAt}
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (autostart) {
      for (const d of this.list()) this.startConnector(d);
      this.renewTimer = setInterval(() => this.renewAll().catch(() => {}), RENEW_EVERY_MS);
      this.renewTimer.unref?.();
    }
  }

  // relay: {configured(), host(), ip(): Promise<ip>, ready(): Promise<{ok, error}>, push(cur, suffix), remove(suffix)}
  useRelay(relay) { this.relay = relay; }

  list() { return (this.settings.get("domains") || []).filter((d) => d?.zone?.name && d.cert); }
  get(zone) { return this.list().find((d) => d.zone.name === String(zone || "").toLowerCase()) || null; }
  save(list) { this.settings.set({ domains: list }); this.onChange?.(list); }
  pendingPath() { return join(this.dir, "pending.pem"); }
  pending() { return existsSync(this.pendingPath()) ? this.settings.get("domainsPending") || null : null; }
  target(d) { return d.tunnelId ? `${d.tunnelId}.cfargotunnel.com` : null; }
  dashboardOf(d) { return d.label ? `${d.label}.${d.zone.name}` : null; }
  suffixOf(d) { return "." + d.zone.name; }
  certBase(d) { return `zone-${d.zone.name}`; }
  subsOf(d) { return Array.isArray(d.subs) ? d.subs : []; }
  // something on the domain is for tunnels: its wildcard, or a subdomain
  hasTunnels(d) { return d.tunnels !== "none" || this.subsOf(d).length > 0; }
  onVps(d) { return d.route === "vps" && this.hasTunnels(d); }
  needsTunnel(d) { return !!d.label || (this.hasTunnels(d) && d.route !== "vps"); }
  // The certificates a domain needs on your VPS: *.<zone> (its wildcard, and every
  // one-level name: the single subdomains), and *.<name>.<zone> for each wildcard subdomain.
  certsOf(d) {
    if (!this.onVps(d)) return [];
    const out = [];
    if (d.tunnels !== "none" || this.subsOf(d).some((x) => !x.wildcard)) out.push({ base: this.certBase(d), name: `*.${d.zone.name}`, suffix: this.suffixOf(d) });
    for (const x of this.subsOf(d)) if (x.wildcard) out.push({ base: `zone-${x.name}.${d.zone.name}`, name: `*.${x.name}.${d.zone.name}`, suffix: `.${x.name}.${d.zone.name}` });
    return out;
  }
  wantsRelay() { return this.list().some((d) => this.onVps(d)); }

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
      const recs = await this.api(d, "GET", "/dns_records?per_page=1000");
      const names = new Set(recs.filter((r) => r.comment !== COMMENT && r.content !== this.target(d) && !r.name.startsWith("*.")).map((r) => r.name.toLowerCase()));
      this.taken.set(d.zone.name, { at: Date.now(), names });
    } catch (e) { this.log("domains: could not read", d.zone.name, "records:", e.message); }
  }

  view() {
    for (const d of this.list()) this.refreshTaken(d).then(() => {}, () => {});
    const p = this.pending(), r = this.relay;
    return {
      cloudflared: !!this.bin(),
      main: this.mainZone() || null,
      vps: r?.configured() ? { host: r.host(), outdated: r.outdated?.() || null, version: r.version?.() || null } : null,
      domains: this.list().map((d) => {
        const c = this.connectors.get(d.zone.name), certs = this.certsOf(d).map((x) => ({ ...x, cur: this.files.read(x.base), st: this.certState.get(x.base) }));
        const ends = certs.map((x) => x.cur?.notAfter || 0), bad = certs.find((x) => x.st?.error);
        return { zone: d.zone.name, label: d.label || "", dashboard: this.dashboardOf(d), tunnels: d.tunnels, route: d.route || "cloudflare", linked: d.linked,
                 example: d.tunnels === "none" ? null : `NAME.${d.zone.name}`,
                 subs: this.subsOf(d).map((x) => ({ ...x, host: x.wildcard ? `*.${x.name}.${d.zone.name}` : `${x.name}.${d.zone.name}`, example: x.wildcard ? `NAME.${x.name}.${d.zone.name}` : null })),
                 cert: certs.length ? { notAfter: ends.every(Boolean) ? Math.min(...ends) : null, issuing: certs.some((x) => x.st?.issuing), error: bad ? bad.st.error : null,
                                        names: certs.map((x) => x.name) } : null,
                 connector: c ? { running: !!c.running, since: c.since || null, log: (c.lines || []).slice(-12) } : null };
      }),
      login: this.login ? { url: this.login.url, error: this.login.error, waiting: !!this.login.proc } : null,
      need: this.need,
      pending: p ? { zone: p.name || null, via: p.via || "login" } : null,
    };
  }

  // ------------------------------------------------------------- access to a domain
  // Every Cloudflare credential Aegis holds: the main domain's, the other domains', your tokens.
  tokens() {
    const out = [];
    const fromCert = (file, why) => { try { if (file && existsSync(file)) out.push({ token: decodeCert(file).token, why }); } catch { /* unreadable */ } };
    fromCert(this.mainCert(), "the main domain's");
    for (const d of this.list()) fromCert(d.cert, `${d.zone.name}'s`);
    for (const t of this.settings.get("cfTokens") || []) if (t?.token) out.push({ token: t.token, why: "your API token" });
    const seen = new Set();
    return out.filter((t) => !seen.has(t.token) && seen.add(t.token));
  }
  // Can this token edit `zone`? -> {zoneId, accountId} or null
  async reach(token, zone) {
    try {
      const z = (await this.cfApi(token, "GET", `/zones?name=${encodeURIComponent(zone)}`))?.[0];
      if (!z?.id || z.name !== zone) return null;
      await this.cfApi(token, "GET", `/zones/${z.id}/dns_records?per_page=1`);
      return { zoneId: z.id, accountId: z.account?.id || null };
    } catch { return null; }
  }
  cleanZone(zone) {
    zone = String(zone || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^\*?\./, "").replace(/\.$/, "");
    if (!ZONE_RE.test(zone)) throw new Error("Type the domain, like example.org.");
    if (zone === this.mainZone()) throw new Error(`${zone} is already the main domain.`);
    if (this.get(zone)) throw new Error(`${zone} is already added.`);
    return zone;
  }
  // Step 1: a domain's name. If something Aegis holds reaches it, it's ready to add; else `need`.
  async check(zone) {
    if (!this.mainZone()) throw new Error("Link the main domain first (above).");
    zone = this.cleanZone(zone);
    this.need = null;
    for (const t of this.tokens()) {
      const z = await this.reach(t.token, zone);
      if (z) { this.setPending({ id: z.zoneId, name: zone, via: t.why }, makeCert({ ...z, token: t.token })); this.log("domains:", zone, "reached with", t.why, "credentials"); return this.view(); }
    }
    this.need = { zone };
    return this.view();
  }
  // An API token for it (kept, and tried first for every domain after)
  async useToken(zone, token) {
    zone = this.cleanZone(zone);
    token = String(token || "").trim();
    if (!/^[A-Za-z0-9_-]{30,200}$/.test(token)) throw new Error("That doesn't look like a Cloudflare API token.");
    const z = await this.reach(token, zone);
    if (!z) { this.need = { zone, error: `That token can't edit ${zone}'s DNS. Give it Zone → DNS → Edit for ${zone} (or all zones).` }; throw new Error(this.need.error); }
    const tokens = (this.settings.get("cfTokens") || []).filter((t) => t.token !== token);
    this.settings.set({ cfTokens: [...tokens, { token, added: Date.now() }] });
    this.setPending({ id: z.zoneId, name: zone, via: "your API token" }, makeCert({ ...z, token }));
    this.need = null;
    return this.view();
  }
  setPending(p, pem) {
    writeFileSync(this.pendingPath(), pem, { mode: 0o600 });
    this.settings.set({ domainsPending: p });
  }

  // Or `cloudflared tunnel login` with a HOME of its own; the cert it receives
  // waits in pending.pem until add() uses it (or forget() drops it).
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
    this.settings.set({ domainsPending: { id: c.zoneId, name, via: "login" } });
    this.need = null;
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
    this.login = null; this.need = null;
    return this.view();
  }

  // ------------------------------------------------------------- add, change, remove
  static clean({ label, tunnels, route, subs } = {}) {
    label = String(label ?? "").trim().toLowerCase();
    if (label && !LABEL_RE.test(label)) throw new Error("The dashboard's name is 1-40 letters, digits and dashes (not at the ends), or empty for none.");
    if (/^\d+$/.test(label)) throw new Error("A name of only digits is how tunnels are reached; add a letter.");
    if (tunnels != null && !MODES.has(tunnels)) throw new Error("Tunnels on it: all, picked or none.");
    if (route != null && !ROUTES.has(route)) throw new Error("Tunnels arrive through your VPS or Cloudflare.");
    return { label, tunnels, route, subs: subs == null ? subs : Domains.cleanSubs(subs) };
  }
  // [{name, wildcard: true} | {name, wildcard: false, port}], one level under the zone each
  static cleanSubs(subs) {
    if (!Array.isArray(subs)) throw new Error("Subdomains are a list.");
    if (subs.length > MAX_SUBS) throw new Error(`Up to ${MAX_SUBS} subdomains on a domain.`);
    const seen = new Set();
    return subs.map((x) => {
      const name = String(x?.name ?? "").trim().toLowerCase().replace(/^\*\./, "");
      if (!LABEL_RE.test(name)) throw new Error(`"${name || " "}" isn't a subdomain: 1-40 letters, digits and dashes (not at the ends), one level (no dots).`);
      if (/^\d+$/.test(name)) throw new Error(`A subdomain of only digits (${name}) is how tunnels are reached by port; add a letter.`);
      if (seen.has(name)) throw new Error(`${name} is there twice.`);
      seen.add(name);
      if (x.wildcard) return { name, wildcard: true };
      const port = Number(x.port);
      if (!Number.isInteger(port) || port < 1 || port > 99999) throw new Error(`Pick the tunnel ${name} goes to.`);
      return { name, wildcard: false, port };
    });
  }
  // what a domain's settings may be together
  validate(d) {
    if (!d.label && !this.hasTunnels(d)) throw new Error("Give it the dashboard, some tunnels, or both. (Or remove the domain.)");
    for (const x of this.subsOf(d)) {
      if (x.name === d.label) throw new Error(`${x.name}.${d.zone.name} is the dashboard's name there; pick another subdomain.`);
      if (!x.wildcard) continue;
      if (d.tunnels === "none") throw new Error(`*.${x.name}.${d.zone.name} carries the same tunnels as the domain: set its tunnels to all or picked first (or make ${x.name} one tunnel's name).`);
      if (d.route !== "vps") throw new Error(`*.${x.name}.${d.zone.name} is two levels under ${d.zone.name}, and Cloudflare's free certificate covers one. Send the domain's tunnels through your VPS (it gets a certificate for it by itself), or make ${x.name} one tunnel's name.`);
    }
  }
  api(d, method, path, body) { const c = decodeCert(d.cert); return this.cfApi(c.token, method, `/zones/${c.zoneId}${path}`, body); }

  async add(spec) {
    const c = Domains.clean(spec);
    const subs = c.subs || [];
    const tunnels = c.tunnels || "all", route = c.route || (this.relay?.configured() ? "vps" : "cloudflare");
    const p = this.pending();
    if (!p?.name) throw new Error("Tell Aegis which domain first.");
    if (this.get(p.name)) throw new Error(`${p.name} is already added.`);
    this.validate({ zone: { name: p.name }, label: c.label, tunnels, route, subs });
    const dir = join(this.dir, p.name);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const cert = join(dir, "cert.pem");
    renameSync(this.pendingPath(), cert);
    let d = { zone: { id: p.id, name: p.name }, label: c.label, tunnels, route, ...(subs.length ? { subs } : {}), cert, linked: Date.now() };
    try {
      if (this.needsTunnel(d)) d = await this.makeTunnel(d);
      if (this.onVps(d)) await this.toVps(d);
      await this.syncRecords(d, null);
    } catch (e) {
      if (d.tunnelId) await this.dropTunnel(d);
      try { renameSync(cert, this.pendingPath()); } catch { /* gone */ }
      rmSync(dir, { recursive: true, force: true });
      throw e;
    }
    this.settings.set({ domainsPending: null });
    this.save([...this.list(), d]);
    this.startConnector(d);
    this.refreshTaken(d, true).then(() => {}, () => {});
    this.log("domains: added", p.name, d.label ? `(dashboard ${this.dashboardOf(d)})` : "", "tunnels:", tunnels, tunnels === "none" ? "" : `through ${route}`);
    return this.view();
  }

  async update(zone, patch) {
    const d = this.get(zone);
    if (!d) throw new Error("No such domain.");
    const c = Domains.clean({ label: "label" in patch ? patch.label : d.label, tunnels: patch.tunnels ?? d.tunnels, route: patch.route ?? d.route ?? "cloudflare", subs: patch.subs ?? this.subsOf(d) });
    let next = { ...d, label: c.label, tunnels: c.tunnels, route: c.route, subs: c.subs };
    if (!next.subs.length) delete next.subs;
    this.validate(next);
    if (this.needsTunnel(next) && !next.tunnelId) next = await this.makeTunnel(next);
    if (this.onVps(next)) await this.toVps(next);                 // the VPS has the certificate before any name points at it
    await this.syncRecords(next, d);
    const keep = new Set(this.certsOf(next).map((x) => x.suffix));
    for (const x of this.certsOf(d)) {
      if (keep.has(x.suffix)) continue;
      await this.relay?.remove(x.suffix).catch((e) => this.log("domains: the VPS kept", x.name, e.message));
      if (x.base !== this.certBase(d)) { for (const f of Object.values(this.files.paths(x.base))) rmSync(f, { force: true }); this.certState.delete(x.base); }
    }
    this.save(this.list().map((x) => (x.zone.name === d.zone.name ? next : x)));
    this.startConnector(next);
    this.log("domains:", d.zone.name, "now", next.label ? `dashboard ${this.dashboardOf(next)},` : "no dashboard,", "tunnels:", next.tunnels, this.hasTunnels(next) ? `through ${next.route}` : "",
             this.subsOf(next).length ? `subdomains: ${this.subsOf(next).map((x) => (x.wildcard ? `*.${x.name}` : `${x.name}→${x.port}`)).join(" ")}` : "");
    return this.view();
  }

  async remove(zone) {
    const d = this.get(zone);
    if (!d) throw new Error("No such domain.");
    this.connectors.get(d.zone.name)?.stop();
    this.connectors.delete(d.zone.name);
    try { await this.syncRecords({ ...d, label: "", tunnels: "none", subs: [] }, d); } catch (e) { this.log("domains: could not remove", d.zone.name, "records:", e.message); }
    for (const x of this.certsOf(d)) await this.relay?.remove(x.suffix).catch((e) => this.log("domains: the VPS kept", x.name, e.message));
    if (d.tunnelId) await this.dropTunnel(d);
    rmSync(join(this.dir, d.zone.name), { recursive: true, force: true });
    for (const x of this.certsOf(d)) { for (const f of Object.values(this.files.paths(x.base))) rmSync(f, { force: true }); this.certState.delete(x.base); }
    this.taken.delete(d.zone.name);
    this.save(this.list().filter((x) => x.zone.name !== d.zone.name));
    this.log("domains: removed", d.zone.name);
    return this.view();
  }

  // ------------------------------------------------------------- the domain's Cloudflare tunnel (only when needed)
  async makeTunnel(d) {
    const bin = this.bin();
    if (!bin) throw new Error("cloudflared is not installed.");
    const dir = join(this.dir, d.zone.name), creds = join(dir, "tunnel.json");
    const name = `aegis-${d.zone.name.replace(/\./g, "-").slice(0, 40)}-${randomBytes(3).toString("hex")}`;
    rmSync(creds, { force: true });
    const r = await this.run(bin, ["--origincert", d.cert, "tunnel", "--no-autoupdate", "create", "--credentials-file", creds, name], { env: { ...process.env, HOME: this.home } });
    const id = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/.exec(r.out + r.err)?.[1];
    if (r.code !== 0 || !id) {
      const why = (r.err || r.out).trim().split("\n").pop();
      throw new Error(/auth|permission|forbidden|10000|9109/i.test(why)
        ? `These credentials can't make a Cloudflare tunnel (${why}). Sign in with Cloudflare instead, or send the tunnels through your VPS with no dashboard on this domain.`
        : `cloudflared could not create the tunnel: ${why}`);
    }
    return { ...d, tunnelId: id, tunnelName: name, creds };
  }
  async dropTunnel(d) {
    const bin = this.bin();
    if (!bin) return;
    const env = { env: { ...process.env, HOME: this.home } };
    await this.run(bin, ["--origincert", d.cert, "tunnel", "cleanup", d.tunnelId], env);
    const r = await this.run(bin, ["--origincert", d.cert, "tunnel", "delete", "-f", d.tunnelId], env);
    if (r.code !== 0) this.log("domains: tunnel delete:", (r.err || r.out).trim().split("\n").pop());
  }

  // ------------------------------------------------------------- your VPS: its certificate
  // The agent is linked (and new enough), this domain's wildcard exists, and the agent has it.
  async toVps(d) {
    const r = this.relay;
    if (!r?.configured()) throw new Error("Link your VPS first (Settings → Domain → Your VPS), or send these tunnels through Cloudflare.");
    const ok = await r.ready();
    if (!ok.ok) throw new Error(`Your VPS (${r.host()}) isn't reachable: ${ok.error}. Nothing was moved.`);
    for (const c of this.certsOf(d)) {
      const cur = await this.ensureCert(d, c, { force: true });
      try { await r.push(cur, c.suffix); }
      catch (e) { throw new Error(`The certificate for ${c.name} couldn't go on your VPS: ${e.message}. Nothing was moved.`); }
    }
  }
  // c: one of certsOf(d)
  async ensureCert(d, c = this.certsOf(d)[0], { force = false } = {}) {
    const cur = this.files.read(c.base), name = c.name;
    if (cur && cur.names.includes(name) && cur.notAfter - Date.now() > RENEW_BEFORE_MS) return cur;
    const st = this.certState.get(c.base) || {};
    if (st.issuing) return st.issuing;
    if (!force && st.retryAt > Date.now()) throw new Error(st.error || "Waiting to try again.");
    st.issuing = (async () => {
      this.log(`domains: asking Let's Encrypt for a certificate for ${name}`);
      try {
        const got = await this.acme.issue([name], {
          set: async (n, value) => (await this.api(d, "POST", "/dns_records", { type: "TXT", name: n, content: value, ttl: 60, comment: "aegis (certificate check)" })).id,
          visible: this.txtVisible,
          remove: (id) => this.api(d, "DELETE", `/dns_records/${id}`),
        });
        const saved = this.files.write(c.base, got, [name], this.acme.directoryUrl);
        this.log(`domains: certificate for ${name} until ${new Date(got.notAfter).toISOString().slice(0, 10)}`);
        this.certState.set(c.base, {});
        return saved;
      } catch (e) {
        this.certState.set(c.base, { error: e.message, retryAt: Date.now() + RETRY_MS });
        this.log("domains: no certificate for", name + ":", e.message);
        throw new Error(`Let's Encrypt didn't give a certificate for ${name}: ${e.message}`);
      }
    })();
    this.certState.set(c.base, st);
    return st.issuing;
  }
  // every VPS domain's certificate: renewed when due, and on the agent (link up, renewal, every few hours)
  async pushAll() {
    for (const d of this.list()) for (const c of this.certsOf(d)) {
      try { await this.relay?.push(await this.ensureCert(d, c), c.suffix); }
      catch (e) { this.log("domains: couldn't put the certificate for", c.name, "on the VPS:", e.message); }
    }
  }
  renewAll() { return this.pushAll(); }

  // ------------------------------------------------------------- DNS records
  // What `d` needs: {name: {type, content, proxied}}
  async records(d) {
    const out = {}, t = this.target(d);
    if (d.label) out[this.dashboardOf(d)] = { type: "CNAME", content: t, proxied: true };
    if (!this.hasTunnels(d)) return out;
    const names = [];
    if (d.tunnels !== "none") names.push(`*.${d.zone.name}`);
    for (const x of this.subsOf(d)) names.push(x.wildcard ? `*.${x.name}.${d.zone.name}` : `${x.name}.${d.zone.name}`);
    let rec;
    if (d.route === "vps") { const ip = await this.relay.ip(); rec = { type: isIP(ip) === 6 ? "AAAA" : "A", content: ip, proxied: false }; }
    else rec = { type: "CNAME", content: t, proxied: true };
    for (const n of names) out[n] = { ...rec };
    return out;
  }
  // The records `d` needs, made first; then the ones `was` had that `d` doesn't, removed.
  // Never takes over a record that isn't ours (mail, www, a website…).
  async syncRecords(d, was) {
    const want = await this.records(d), had = was ? await this.records(was).catch(() => ({})) : {};
    const ours = (r) => r.comment === COMMENT || (r.type === "CNAME" && (r.content === this.target(d) || (was && r.content === this.target(was))));
    for (const [name, rec] of Object.entries(want)) {
      const h = had[name];
      if (h && h.type === rec.type && h.content === rec.content && h.proxied === rec.proxied) continue;
      const cur = (await this.api(d, "GET", `/dns_records?name=${encodeURIComponent(name)}`)).filter((r) => r.name === name);
      if (cur.some((r) => r.type === rec.type && r.content === rec.content && !!r.proxied === rec.proxied)) continue;
      const theirs = cur.find((r) => !ours(r));
      if (theirs) {
        throw new Error(`${name} already has a ${theirs.type} record${theirs.content ? ` (${theirs.content})` : ""}. ${name === `*.${d.zone.name}` ? "Delete it on Cloudflare first, or set tunnels to none." : name.startsWith("*.") ? "Delete it on Cloudflare first, or pick another subdomain." : "Pick another name, or none."}`);
      }
      const body = { type: rec.type, name, content: rec.content, proxied: rec.proxied, ttl: 1, comment: COMMENT };
      const same = cur.find((r) => r.type === rec.type);
      for (const r of cur) if (r !== same) await this.api(d, "DELETE", `/dns_records/${r.id}`);
      if (same) await this.api(d, "PUT", `/dns_records/${same.id}`, body);
      else await this.api(d, "POST", "/dns_records", body);
    }
    for (const name of Object.keys(had)) {
      if (want[name]) continue;
      const cur = (await this.api(d, "GET", `/dns_records?name=${encodeURIComponent(name)}`)).filter((r) => r.name === name);
      for (const r of cur) if (ours(r)) await this.api(d, "DELETE", `/dns_records/${r.id}`);
    }
  }

  // ------------------------------------------------------------- connectors (only for a domain with a tunnel in use)
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
      ...this.subsOf(d).filter((x) => !x.wildcard).flatMap((x) => rule(`${x.name}.${d.zone.name}`)),
      ...rule(`*.${d.zone.name}`),
      "  - service: http_status:404",
    ].filter(Boolean).join("\n") + "\n";
    const file = join(this.dir, d.zone.name, "cloudflared.yml");
    writeFileSync(file, yml, { mode: 0o600 });
    return file;
  }
  startConnector(d) {
    const bin = this.bin(), want = d.tunnelId && this.needsTunnel(d) && existsSync(d.creds || "");
    let sup = this.connectors.get(d.zone.name);
    if (!want || !bin) { if (sup) { sup.stop(); this.connectors.delete(d.zone.name); } return; }
    const file = this.writeConfig(d);
    if (sup) sup.stop();
    else { sup = new Supervised(`connector ${d.zone.name}`, this.log); this.connectors.set(d.zone.name, sup); }
    sup.start(bin, ["--no-autoupdate", "--config", file, "tunnel", "--post-quantum", "run"], { HOME: this.home });
  }
  stop() { clearInterval(this.renewTimer); for (const s of this.connectors.values()) s.stop(); this.cancelLogin(); }
}
