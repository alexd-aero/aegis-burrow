// The edge: wildcard tunnels answered on this machine's own certificate.
//
// With naming {mode: "wildcard", certs: "self"}, the machine Aegis runs on is
// where *.<prefix>.<zone> ends: it holds a Let's Encrypt certificate for it
// (acme.mjs, DNS-01 through the linked Cloudflare token, renewed 30 days
// before it runs out) and Aegis serves the tunnels with it on a port of its
// own (aegis/server.mjs: 443 when it may, else 8443). The wildcard is a plain A
// record (not through Cloudflare's proxy), so Cloudflare's certificate rules
// don't matter and nobody in between holds a key.
//
// Where the A record points:
//   direct   this machine's public address, once it's reachable on port 443
//            from there (the router forwards 443 to the edge port; Burrow asks
//            for that over UPnP). Checked every minute from the outside:
//            edge-check-<label>.<zone> is a Cloudflare-proxied record to the
//            public address (one level, so Cloudflare's free certificate
//            covers it; ours does too), and Burrow fetches a token of its own
//            through it, so Cloudflare connects to port 443 here the way a
//            visitor would. (Asking the public address from inside the house
//            proves nothing: many routers don't loop back, or answer with
//            their own admin page. That is only tried second.)
//   relay    the relay (naming.relay, a server with Caddy) while it isn't:
//            three failed checks in a row move the record there, two good ones
//            bring it back. A relay with Caddy's layer4 module passes the
//            encrypted bytes of these names through to this machine unopened
//            (aegis/server.mjs, the relay port), so the certificate is still
//            this one; Burrow checks for that too (relayPass). Only when this
//            machine can't be reached does the relay answer with its own.
// With no relay the record stays on this machine's address either way.

import { createSecureContext, connect as tlsConnect } from "node:tls";
import { execFile } from "node:child_process";
import { networkInterfaces } from "node:os";
import { isIP } from "node:net";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Acme, CertFiles, LETSENCRYPT } from "./acme.mjs";

const RENEW_BEFORE_MS = 30 * 864e5;
const CHECK_EVERY_MS = 60e3;
const UPNP_EVERY_MS = 6 * 3600e3;
const RETRY_MS = 3600e3;               // after a failed issue
const FAILS_TO_LEAVE = 3, OKS_TO_RETURN = 2;
const CURVES = ["X25519MLKEM768:X25519:P-256", "X25519:P-256"];
const CHECK_COMMENT = "aegis (edge check)";
export const CHECK_PATH = "/__aegis-edge-check";

const run = (cmd, args, timeout = 30000) => new Promise((resolve) =>
  execFile(cmd, args, { timeout }, (e, out, err) => resolve({ ok: !e, out: String(out || "") + String(err || ""), missing: e?.code === "ENOENT" })));

// Do Cloudflare's and Google's public resolvers both return this TXT value?
async function txtVisible(name, value) {
  const ask = (url) => fetch(url + `?name=${encodeURIComponent(name)}&type=TXT`, { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) })
    .then((r) => r.json()).then((j) => (j.Answer || []).some((a) => String(a.data).replace(/"/g, "") === value)).catch(() => false);
  const [a, b] = await Promise.all([ask("https://cloudflare-dns.com/dns-query"), ask("https://dns.google/resolve")]);
  return a && b;
}

export class Edge {
  // cfApi(method, path, body): the zone's Cloudflare API (TunnelManager.cfApi)
  constructor({ dataDir, log, cfApi, port = 8443, upnp = true, directory } = {}) {
    this.log = log || console.log;
    this.cfApi = cfApi;
    this.port = Number(port) || 8443;
    this.upnpOn = upnp !== false;
    const dir = join(dataDir, "certs");
    this.files = new CertFiles(dir);
    this.acme = new Acme({ dir, directory: directory || process.env.AEGIS_ACME_DIRECTORY || LETSENCRYPT, log: this.log });
    this.base = null;          // tunnel.example.com: the edge serves *.<base>
    this.relay = null;         // the backup relay's IP
    this.cur = null;           // {key, cert, notAfter, fingerprint, names, issued}
    this.ctx = null;
    this.issuing = null;
    this.error = null;
    this.retryAt = 0;
    this.publicIp = null;
    this.direct = { ok: null, fails: 0, oks: 0, checked: null, why: null };
    this.relayPass = null;     // does the relay hand back our own certificate? (passthrough)
    this.upnp = { at: 0, ok: null, note: null, lan: null };
    this.onChange = null;      // where the record should point changed
    this.onCert = null;        // a certificate is ready (first one, or renewed)
    this.timer = null;
    this.checkName = null;     // edge-check-<label>.<zone>: the outside check (see above)
    this.checkToken = randomBytes(16).toString("hex");
    this.checkRec = null;
  }

  // What the certificate covers.
  names() { return this.base ? [`*.${this.base}`, ...(this.checkName ? [this.checkName] : [])] : []; }

  // Serve *.<base> (or nothing: null), with `relay` as the backup.
  use(base, relay, checkName) {
    relay = relay || null;
    checkName = base ? checkName || null : null;
    const before = this.target()?.ip;
    if (this.checkRec && this.checkRec.name !== checkName) this.dropCheckRecord(this.checkRec);
    if (base !== this.base || checkName !== this.checkName) {
      this.base = base || null;
      this.checkName = checkName;
      this.cur = this.base ? this.files.read(this.base) : null;
      if (this.cur && !this.names().every((n) => this.cur.names.includes(n))) this.cur = null;     // a certificate for other names
      this.ctx = null;
      this.error = null;
      this.retryAt = 0;
      this.direct = { ok: null, fails: 0, oks: 0, checked: null, why: null };
      if (this.cur) this.onCert?.();
    }
    this.relay = relay;
    if (this.base && !this.timer) {
      this.timer = setInterval(() => this.tick(), CHECK_EVERY_MS);
      this.timer.unref?.();
      setTimeout(() => this.tick(), 1500).unref?.();
    } else if (!this.base && this.timer) { this.stop(); this.onStop?.(); }
    if (this.target()?.ip !== before) this.onChange?.();
  }
  stop() { clearInterval(this.timer); this.timer = null; }
  ready() { return !!(this.base && this.cur); }
  // (onStop: set by Aegis, called when the edge stops serving)

  async tick() {
    if (!this.base || !this.timer || this._ticking) return;
    this._ticking = true;
    try {
      await this.ensureCert().catch(() => { /* kept in this.error */ });
      await this.refreshIp();
      if (this.upnpOn && Date.now() - this.upnp.at > UPNP_EVERY_MS) await this.mapPort();
      await this.check();
    } finally { this._ticking = false; }
  }

  // ------------------------------------------------------------ the certificate
  fresh(c = this.cur) { return !!c && c.notAfter - Date.now() > RENEW_BEFORE_MS; }
  async ensureCert({ force = false } = {}) {
    if (!this.base) throw new Error("No wildcard to get a certificate for.");
    if (this.fresh()) return this.cur;
    if (this.issuing) return this.issuing;
    if (!force && Date.now() < this.retryAt) throw new Error(this.error || "Waiting to try again.");
    const base = this.base, names = this.names();
    this.issuing = (async () => {
      this.log(`edge: asking Let's Encrypt for a certificate for ${names[0]}`);
      try {
        const c = await this.acme.issue(names, {
          set: async (name, value) => (await this.cfApi("POST", "/dns_records", { type: "TXT", name, content: value, ttl: 60, comment: "aegis (certificate check)" })).id,
          visible: txtVisible,
          remove: (id) => this.cfApi("DELETE", `/dns_records/${id}`),
        });
        const saved = this.files.write(base, c, names, this.acme.directoryUrl);
        if (this.base === base) {
          this.cur = saved; this.ctx = null; this.error = null; this.retryAt = 0;
          this.log(`edge: certificate for ${names[0]} until ${new Date(c.notAfter).toISOString().slice(0, 10)}`);
          this.onCert?.();
        }
        return saved;
      } catch (e) {
        this.error = e.message;
        this.retryAt = Date.now() + RETRY_MS;
        this.log("edge: no certificate:", e.message);
        throw e;
      } finally { this.issuing = null; }
    })();
    return this.issuing;
  }

  // The TLS context for a name the edge serves (one level under base), or null.
  context(servername) {
    const name = String(servername || "").toLowerCase();
    if (!this.cur || !this.base) return null;
    if (name !== this.checkName || !this.cur.names.includes(name)) {
      if (!name.endsWith("." + this.base) || name.slice(0, -this.base.length - 1).includes(".")) return null;
    }
    if (!this.ctx) {
      for (const ecdhCurve of CURVES) {
        try { this.ctx = createSecureContext({ key: this.cur.key, cert: this.cur.cert, minVersion: "TLSv1.2", ecdhCurve }); break; }
        catch { /* an older OpenSSL: the next list */ }
      }
    }
    return this.ctx;
  }

  // ------------------------------------------------------------ reachability
  async refreshIp() {
    const tries = ["https://1.1.1.1/cdn-cgi/trace", "https://www.cloudflare.com/cdn-cgi/trace"];
    for (const u of tries) {
      try {
        const t = await (await fetch(u, { signal: AbortSignal.timeout(6000) })).text();
        const ip = /^ip=(.+)$/m.exec(t)?.[1]?.trim();
        if (ip && isIP(ip) === 4) {
          if (ip !== this.publicIp) {
            const before = this.target()?.ip;
            if (this.publicIp) this.log(`edge: this machine's public address is now ${ip}`);
            this.publicIp = ip;
            if (this.target()?.ip !== before) this.onChange?.();
          }
          return ip;
        }
      } catch { /* the next */ }
    }
    return this.publicIp;
  }

  // Can the internet reach port 443 here? Through Cloudflare first, then the
  // public address itself.
  async probe() {
    if (!this.cur || !this.publicIp) return { ok: false, why: !this.cur ? "no certificate yet" : "no public address yet" };
    const viaCf = this.checkName && this.cur.names.includes(this.checkName) ? await this.probeOutside() : null;
    if (viaCf?.ok) return viaCf;
    const loop = await this.probeLoopback();
    return loop.ok ? loop : viaCf || loop;
  }
  // The outside check record: proxied, to the public address.
  async ensureCheckRecord() {
    if (this.checkRec?.name === this.checkName && this.checkRec.content === this.publicIp) return;
    const name = this.checkName;
    const rec = (await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(name)}`)).find((r) => r.name === name);
    if (rec && rec.comment !== CHECK_COMMENT) throw new Error(`${name} already has a record that isn't Aegis's`);
    const body = { type: "A", name, content: this.publicIp, proxied: true, ttl: 1, comment: CHECK_COMMENT };
    const r = rec ? await this.cfApi("PUT", `/dns_records/${rec.id}`, body) : await this.cfApi("POST", "/dns_records", body);
    this.checkRec = { id: r.id || rec?.id, name, content: this.publicIp };
  }
  dropCheckRecord(rec) {
    this.checkRec = null;
    (async () => {
      const recs = await this.cfApi("GET", `/dns_records?name=${encodeURIComponent(rec.name)}`);
      for (const r of recs) if (r.comment === CHECK_COMMENT) await this.cfApi("DELETE", `/dns_records/${r.id}`);
    })().catch((e) => this.log("edge: couldn't remove", rec.name, e.message));
  }
  async probeOutside() {
    try { await this.ensureCheckRecord(); } catch (e) { return { ok: false, why: `no check record: ${e.message}` }; }
    try {
      const r = await fetch(`https://${this.checkName}${CHECK_PATH}?n=${Date.now()}`, { signal: AbortSignal.timeout(15000), headers: { "Cache-Control": "no-cache" } });
      const body = (await r.text()).trim();
      if (r.ok && body === this.checkToken) return { ok: true };
      return { ok: false, why: { 521: "port 443 is closed there (Cloudflare couldn't connect)", 522: "port 443 doesn't answer there (Cloudflare timed out)",
                                 523: "Cloudflare can't reach that address", 525: "Cloudflare reached port 443 there but the TLS handshake failed",
                                 526: "Cloudflare reached port 443 there but didn't accept the certificate" }[r.status]
                                || `something else answers on port 443 there (HTTP ${r.status} through Cloudflare)` };
    } catch (e) { return { ok: false, why: `the check through Cloudflare failed (${e.cause?.code || e.message})` }; }
  }
  // Our own certificate back through the public address (needs a router that loops back).
  probeLoopback() {
    return new Promise((resolve) => {
      const sock = tlsConnect({ host: this.publicIp, port: 443, servername: `burrow-check.${this.base}`, rejectUnauthorized: false, timeout: 6000 }, () => {
        const fp = sock.getPeerCertificate()?.fingerprint256;
        sock.destroy();
        resolve(fp === this.cur.fingerprint ? { ok: true } : { ok: false, why: "something else answers on port 443 there" });
      });
      sock.on("error", (e) => resolve({ ok: false, why: e.code === "ECONNREFUSED" ? "port 443 is closed there" : e.code === "ETIMEDOUT" ? "port 443 doesn't answer there" : e.message }));
      sock.on("timeout", () => { sock.destroy(); resolve({ ok: false, why: "port 443 doesn't answer there" }); });
    });
  }
  // Through the relay, is it still our certificate? (it passes the bytes through)
  probeRelay() {
    return new Promise((resolve) => {
      if (!this.relay || !this.cur) return resolve(null);
      const sock = tlsConnect({ host: this.relay, port: 443, servername: `burrow-check.${this.base}`, rejectUnauthorized: false, timeout: 8000 }, () => {
        const fp = sock.getPeerCertificate()?.fingerprint256;
        sock.destroy();
        resolve(fp === this.cur.fingerprint);
      });
      sock.on("error", () => resolve(false));
      sock.on("timeout", () => { sock.destroy(); resolve(false); });
    });
  }
  async check() {
    if (!this.base) return;
    const before = this.target()?.ip;
    this.relayPass = await this.probeRelay();
    const r = await this.probe();
    const d = this.direct;
    d.checked = Date.now(); d.why = r.ok ? null : r.why;
    if (r.ok) { d.oks++; d.fails = 0; if (d.ok !== true && (d.ok === null || d.oks >= OKS_TO_RETURN)) d.ok = true; }
    else { d.fails++; d.oks = 0; if (d.ok !== false && (d.ok === null || d.fails >= FAILS_TO_LEAVE)) d.ok = false; }
    const after = this.target()?.ip;
    if (after !== before) {
      this.log(`edge: *.${this.base} ${this.via() === "direct" ? `now goes straight to this machine (${after})` : `now goes through the backup relay (${after}): ${d.why}`}`);
      this.onChange?.();
    }
  }

  via() { return this.direct.ok ? "direct" : this.relay ? "relay" : "direct"; }
  // Where the wildcard record should point: {ip, via, verified} or null (no address known yet)
  target() {
    if (!this.base) return null;
    if (this.direct.ok && this.publicIp) return { ip: this.publicIp, via: "direct", verified: true };
    if (this.relay) return { ip: this.relay, via: "relay", verified: false };
    return this.publicIp ? { ip: this.publicIp, via: "direct", verified: false } : null;
  }

  // ------------------------------------------------------------ the router
  async mapPort() {
    this.upnp.at = Date.now();
    const s = await run("upnpc", ["-s"], 20000);
    if (s.missing) { this.upnp = { ...this.upnp, ok: null, note: "upnpc isn't installed (miniupnpc), so Aegis can't ask the router" }; return; }
    const lan = /Local LAN ip address\s*:\s*([\d.]+)/.exec(s.out)?.[1] || null;
    if (!lan) { this.upnp = { ...this.upnp, ok: false, note: "no UPnP router answered", lan: null }; return; }
    const r = await run("upnpc", ["-e", "aegis tunnels", "-a", lan, String(this.port), "443", "TCP", "86400"], 30000);
    const fail = /failed with code (\d+)\s*\(([^)]*)\)/.exec(r.out);
    this.upnp = fail ? { at: this.upnp.at, ok: false, lan, note: `the router refused port 443 (${fail[1]} ${fail[2]})` }
      : /is redirected to/.test(r.out) ? { at: this.upnp.at, ok: true, lan, note: null }
      : { at: this.upnp.at, ok: false, lan, note: "the router didn't confirm the mapping" };
  }
  lanIp() {
    if (this.upnp.lan) return this.upnp.lan;
    for (const list of Object.values(networkInterfaces())) {
      for (const a of list || []) if (a.family === "IPv4" && !a.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address)) return a.address;
    }
    return null;
  }

  state() {
    const t = this.target();
    return {
      base: this.base, port: this.port, publicIp: this.publicIp, lan: this.lanIp(), relay: this.relay,
      cert: this.cur ? { names: this.cur.names, notAfter: this.cur.notAfter, issued: this.cur.issued,
                         staging: !!this.cur.directory && this.cur.directory !== LETSENCRYPT } : null,
      issuing: !!this.issuing, error: this.error,
      direct: { ok: this.direct.ok, checked: this.direct.checked, why: this.direct.why },
      via: t?.via || null, target: t?.ip || null, relayPass: this.relayPass,
      upnp: { ok: this.upnp.ok, note: this.upnp.note, at: this.upnp.at || null },
    };
  }
}
