// A small ACME client (RFC 8555): just enough to get one wildcard certificate
// from Let's Encrypt by DNS-01, with the Cloudflare token Burrow already holds.
//
// Why it exists: Cloudflare's free edge certificate covers *.<zone> but not
// *.<prefix>.<zone>, so radio.tunnel.example.com can't go through Cloudflare's
// proxy without a paid certificate. With this, the machine Aegis runs on holds
// a real certificate for *.<prefix>.<zone> itself (edge.mjs serves it), and the
// wildcard record points straight at it. No relay server sees the traffic.
//
// No dependencies: node:crypto signs (ES256) and a few lines of DER build the
// certificate request.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";

export const LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory";
export const LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

const b64u = (b) => Buffer.from(b).toString("base64url");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ DER
function derLen(n) {
  if (n < 128) return Buffer.from([n]);
  const b = [];
  while (n) { b.unshift(n & 255); n >>= 8; }
  return Buffer.from([0x80 | b.length, ...b]);
}
const tlv = (tag, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]); };
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
function oid(s) {
  const a = s.split(".").map(Number), out = [40 * a[0] + a[1]];
  for (const n of a.slice(2)) {
    const b = [n & 127];
    for (let v = n >> 7; v; v >>= 7) b.unshift((v & 127) | 128);
    out.push(...b);
  }
  return tlv(0x06, Buffer.from(out));
}

// A PKCS#10 certificate request for `names` (the first one is also the CN), signed with `key`.
export function makeCsr(names, key) {
  const priv = typeof key === "string" ? createPrivateKey(key) : key;
  const pub = createPublicKey(priv).export({ type: "spki", format: "der" });
  const cn = names[0].length <= 64 ? seq(set(seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from(names[0]))))) : seq();
  const san = seq(...names.map((n) => tlv(0x82, Buffer.from(n))));
  const ext = seq(seq(oid("2.5.29.17"), tlv(0x04, san)));
  const attrs = tlv(0xa0, seq(oid("1.2.840.113549.1.9.14"), set(ext)));
  const info = seq(Buffer.from([0x02, 0x01, 0x00]), cn, pub, attrs);
  const sig = sign("sha256", info, priv);                       // DER-encoded ECDSA
  return seq(info, seq(oid("1.2.840.10045.4.3.2")), tlv(0x03, Buffer.concat([Buffer.from([0]), sig])));
}
// ------------------------------------------------------------------ the client
export class Acme {
  // dir: where the account key lives (acme-account.json)
  constructor({ dir, directory = LETSENCRYPT, log = console.log, fetchImpl = fetch }) {
    this.dir = dir;
    this.directoryUrl = directory;
    this.log = log;
    this.fetch = fetchImpl;
    this.nonce = null;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  account() {
    if (this._acct) return this._acct;
    const p = join(this.dir, "acme-account.json");
    let a = null;
    try { a = JSON.parse(readFileSync(p, "utf8")); } catch { /* none yet */ }
    if (!a || a.directory !== this.directoryUrl) {
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      a = { directory: this.directoryUrl, key: privateKey.export({ type: "pkcs8", format: "pem" }), kid: null };
      this.saveAccount(a);
    }
    const key = createPrivateKey(a.key);
    const { crv, kty, x, y } = key.export({ format: "jwk" });
    const jwk = { crv, kty, x, y };                                   // the members of a thumbprint, in order
    this._acct = { ...a, keyObj: key, jwk, thumb: b64u(createHash("sha256").update(JSON.stringify(jwk)).digest()) };
    return this._acct;
  }
  saveAccount(a) {
    const p = join(this.dir, "acme-account.json"), tmp = p + ".tmp";
    writeFileSync(tmp, JSON.stringify({ directory: a.directory, key: a.key, kid: a.kid }, null, 2), { mode: 0o600 });
    renameSync(tmp, p);
  }

  async directory() {
    if (!this._dir) {
      const r = await this.fetch(this.directoryUrl, { signal: AbortSignal.timeout(20000) });
      if (!r.ok) throw new Error(`ACME directory: HTTP ${r.status}`);
      this._dir = await r.json();
    }
    return this._dir;
  }
  async freshNonce() {
    const r = await this.fetch((await this.directory()).newNonce, { method: "HEAD", signal: AbortSignal.timeout(20000) });
    const n = r.headers.get("replay-nonce");
    if (!n) throw new Error("ACME: no nonce");
    return n;
  }

  // A signed POST. payload null = POST-as-GET.
  async post(url, payload, { useJwk = false, accept } = {}) {
    const a = this.account();
    for (let attempt = 0; ; attempt++) {
      const nonce = this.nonce || await this.freshNonce();
      this.nonce = null;
      const prot = { alg: "ES256", nonce, url, ...(useJwk || !a.kid ? { jwk: a.jwk } : { kid: a.kid }) };
      const p64 = b64u(JSON.stringify(prot)), b64 = payload === null ? "" : b64u(JSON.stringify(payload));
      const sig = sign("sha256", Buffer.from(`${p64}.${b64}`), { key: a.keyObj, dsaEncoding: "ieee-p1363" });
      const r = await this.fetch(url, {
        method: "POST", signal: AbortSignal.timeout(30000),
        headers: { "Content-Type": "application/jose+json", ...(accept ? { Accept: accept } : {}) },
        body: JSON.stringify({ protected: p64, payload: b64, signature: b64u(sig) }),
      });
      this.nonce = r.headers.get("replay-nonce") || null;
      const type = r.headers.get("content-type") || "";
      const body = type.includes("json") ? await r.json().catch(() => ({})) : await r.text();
      if (r.status === 400 && body?.type === "urn:ietf:params:acme:error:badNonce" && attempt < 4) continue;
      if (r.status >= 400) {
        const e = new Error(`ACME: ${body?.detail || body?.type || `HTTP ${r.status}`}`);
        e.acme = body;
        throw e;
      }
      return { status: r.status, body, location: r.headers.get("location") };
    }
  }

  async register() {
    const a = this.account();
    if (a.kid) return a.kid;
    // Let's Encrypt's Subscriber Agreement: https://letsencrypt.org/repository/
    const r = await this.post((await this.directory()).newAccount, { termsOfServiceAgreed: true }, { useJwk: true });
    a.kid = r.location;
    this.saveAccount(a);
    this.log("acme: account ready");
    return a.kid;
  }

  // Wait for an order/authorization/challenge to leave "pending"/"processing".
  async poll(url, done, { tries = 60, every = 2000 } = {}) {
    for (let i = 0; i < tries; i++) {
      const r = await this.post(url, null);
      if (done(r.body)) return r.body;
      if (r.body.status === "invalid") {
        const why = r.body.error?.detail || (r.body.challenges || []).map((c) => c.error?.detail).filter(Boolean).join("; ");
        throw new Error(`ACME: ${why || "the request was refused"}`);
      }
      await sleep(every);
    }
    throw new Error("ACME: timed out waiting for Let's Encrypt");
  }

  // One certificate for `names` (e.g. ["*.tunnel.example.com"]), proving
  // control with TXT records:
  //   dns.set(name, value) -> handle      dns.visible(name, value) -> bool      dns.remove(handle)
  // Returns {key, cert, notAfter} (PEM).
  async issue(names, dns) {
    await this.register();
    const d = await this.directory();
    const order = await this.post(d.newOrder, { identifiers: names.map((value) => ({ type: "dns", value })) });
    const orderUrl = order.location;
    const made = [];
    try {
      const pending = [];
      for (const az of order.body.authorizations) {
        const a = (await this.post(az, null)).body;
        if (a.status === "valid") continue;
        const ch = a.challenges.find((c) => c.type === "dns-01");
        if (!ch) throw new Error("ACME: Let's Encrypt offered no DNS challenge");
        const value = b64u(createHash("sha256").update(`${ch.token}.${this.account().thumb}`).digest());
        const name = `_acme-challenge.${a.identifier.value}`;
        made.push(await dns.set(name, value));
        pending.push({ az, ch, name, value });
      }
      for (const p of pending) {
        // until public DNS answers with it, Let's Encrypt might not see it either
        const t0 = Date.now();
        while (!(await dns.visible(p.name, p.value))) {
          if (Date.now() - t0 > 180000) throw new Error(`The ${p.name} record didn't show up in public DNS within 3 minutes.`);
          await sleep(4000);
        }
      }
      if (pending.length) await sleep(5000);
      for (const p of pending) await this.post(p.ch.url, {});
      for (const p of pending) await this.poll(p.az, (b) => b.status === "valid");

      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const csr = makeCsr(names, privateKey);
      let o = (await this.post(order.body.finalize, { csr: b64u(csr) })).body;
      if (o.status !== "valid") o = await this.poll(orderUrl, (b) => b.status === "valid" && b.certificate, { tries: 90 });
      const cert = (await this.post(o.certificate, null, { accept: "application/pem-certificate-chain" })).body;
      if (typeof cert !== "string" || !cert.includes("BEGIN CERTIFICATE")) throw new Error("ACME: no certificate came back");
      const notAfter = Date.parse(new X509Certificate(cert).validTo);
      return { key: privateKey.export({ type: "pkcs8", format: "pem" }), cert, notAfter };
    } finally {
      for (const h of made) { try { await dns.remove(h); } catch (e) { this.log("acme: couldn't remove a challenge record:", e.message); } }
    }
  }
}

// ------------------------------------------------------------------ where certificates are kept
// <dir>/<base>.key, <base>.crt, <base>.json ({names, notAfter, issued, directory})
export class CertFiles {
  constructor(dir) { this.dir = dir; mkdirSync(dir, { recursive: true, mode: 0o700 }); }
  paths(base) { return { key: join(this.dir, `${base}.key`), crt: join(this.dir, `${base}.crt`), meta: join(this.dir, `${base}.json`) }; }
  read(base) {
    const p = this.paths(base);
    if (!existsSync(p.key) || !existsSync(p.crt)) return null;
    try {
      const cert = readFileSync(p.crt, "utf8"), x = new X509Certificate(cert);
      let meta = {};
      try { meta = JSON.parse(readFileSync(p.meta, "utf8")); } catch { /* older */ }
      return { key: readFileSync(p.key, "utf8"), cert, notAfter: Date.parse(x.validTo), fingerprint: x.fingerprint256,
               names: meta.names || [], issued: meta.issued || null, directory: meta.directory || null };
    } catch { return null; }
  }
  write(base, { key, cert, notAfter }, names, directory) {
    const p = this.paths(base);
    const put = (f, data, mode) => { writeFileSync(f + ".tmp", data, { mode }); renameSync(f + ".tmp", f); };
    put(p.key, key, 0o600);
    put(p.crt, cert, 0o644);
    put(p.meta, JSON.stringify({ names, notAfter, issued: Date.now(), directory }, null, 2), 0o644);
    return this.read(base);
  }
}
