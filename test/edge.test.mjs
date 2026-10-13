// This machine as the certificate holder: the ACME client against a fake
// Let's Encrypt, the certificate request against openssl, and the wildcard
// record moving between this machine and the backup relay.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { Acme, makeCsr } from "../burrow/acme.mjs";
import { TunnelManager, cleanNaming } from "../burrow/tunnels.mjs";

const tmp = (p) => mkdtempSync(join(tmpdir(), p));
const haveOpenssl = (() => { try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; } catch { return false; } })();

// a self-signed certificate for `name`, standing in for what Let's Encrypt sends
function selfSigned(name) {
  const d = tmp("edge-ss-");
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "90",
    "-subj", "/CN=" + name, "-addext", `subjectAltName=DNS:${name}`, "-keyout", join(d, "k.pem"), "-out", join(d, "c.pem")], { stdio: "ignore" });
  return readFileSync(join(d, "c.pem"), "utf8");
}

test("the certificate request is one openssl accepts, with the wildcard in it", { skip: !haveOpenssl && "no openssl" }, () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = makeCsr(["*.tunnel.example.com"], privateKey);
  const d = tmp("edge-csr-");
  writeFileSync(join(d, "csr.der"), der);
  const out = execFileSync("openssl", ["req", "-inform", "DER", "-in", join(d, "csr.der"), "-noout", "-verify", "-text"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  assert.match(out, /DNS:\*\.tunnel\.example\.com/);
  assert.match(out, /CN\s*=\s*\*\.tunnel\.example\.com/);
});

// Just enough of RFC 8555 to drive Acme.issue, checking every signature.
function fakeLetsEncrypt(certPem) {
  const st = { nonces: new Set(), accounts: new Map(), order: null, txtWanted: null, finalized: false, posts: 0 };
  let base = "";
  const nonce = () => { const n = "n" + Math.random().toString(36).slice(2); st.nonces.add(n); return n; };
  const srv = createServer((req, res) => {
    const reply = (status, body, headers = {}) => {
      res.writeHead(status, { "Replay-Nonce": nonce(), "Content-Type": typeof body === "string" ? "application/pem-certificate-chain" : "application/json", ...headers });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (req.url === "/dir") return reply(200, { newNonce: base + "/nonce", newAccount: base + "/acct", newOrder: base + "/order" });
    if (req.url === "/nonce") return reply(200, {});
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      st.posts++;
      const jws = JSON.parse(raw), prot = JSON.parse(Buffer.from(jws.protected, "base64url"));
      if (!st.nonces.delete(prot.nonce)) return reply(400, { type: "urn:ietf:params:acme:error:badNonce" });
      assert.equal(prot.url, base + req.url, "the url is signed");
      const jwk = prot.jwk || st.accounts.get(prot.kid);
      assert.ok(jwk, "a known account");
      const ok = verify("sha256", Buffer.from(`${jws.protected}.${jws.payload}`), { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(jws.signature, "base64url"));
      assert.ok(ok, "the signature checks out");
      const payload = jws.payload ? JSON.parse(Buffer.from(jws.payload, "base64url")) : null;
      const thumb = createHash("sha256").update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest("base64url");
      if (req.url === "/acct") {
        assert.equal(payload.termsOfServiceAgreed, true);
        st.accounts.set(base + "/acct/1", jwk);
        return reply(201, { status: "valid" }, { Location: base + "/acct/1" });
      }
      if (req.url === "/order") {
        assert.deepEqual(payload.identifiers, [{ type: "dns", value: "*.tunnel.example.com" }]);
        st.txtWanted = createHash("sha256").update(`tok123.${thumb}`).digest("base64url");
        return reply(201, { status: "pending", authorizations: [base + "/authz"], finalize: base + "/finalize" }, { Location: base + "/order/1" });
      }
      if (req.url === "/authz") {
        return reply(200, { status: st.challenged ? "valid" : "pending", identifier: { type: "dns", value: "tunnel.example.com" }, wildcard: true,
                            challenges: [{ type: "http-01", url: base + "/ch-http", token: "x" }, { type: "dns-01", url: base + "/ch", token: "tok123" }] });
      }
      if (req.url === "/ch") {
        assert.equal(st.txtSeen, st.txtWanted, "the TXT record holds the key authorization's digest");
        st.challenged = true;
        return reply(200, { status: "processing" });
      }
      if (req.url === "/finalize") {
        const der = Buffer.from(payload.csr, "base64url");
        assert.ok(der.includes(Buffer.from("*.tunnel.example.com")), "the request names the wildcard");
        st.finalized = true;
        return reply(200, { status: "processing" });
      }
      if (req.url === "/order/1") return reply(200, st.finalized ? { status: "valid", certificate: base + "/cert" } : { status: "pending" });
      if (req.url === "/cert") return reply(200, certPem);
      reply(404, { type: "notFound" });
    });
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => { base = `http://127.0.0.1:${srv.address().port}`; resolve({ srv, st, url: base + "/dir" }); }));
}

test("ACME: account, order, DNS challenge, certificate; the TXT record is cleaned up", { skip: !haveOpenssl && "no openssl" }, async () => {
  const pem = selfSigned("*.tunnel.example.com");
  const { srv, st, url } = await fakeLetsEncrypt(pem);
  try {
    const acme = new Acme({ dir: tmp("edge-acme-"), directory: url, log: () => {} });
    const records = new Map();
    const dns = {
      set: async (name, value) => { assert.equal(name, "_acme-challenge.tunnel.example.com"); records.set("rec1", value); st.txtSeen = value; return "rec1"; },
      visible: async (name, value) => records.get("rec1") === value,
      remove: async (id) => { records.delete(id); },
    };
    const c = await acme.issue(["*.tunnel.example.com"], dns);
    assert.match(c.cert, /BEGIN CERTIFICATE/);
    assert.match(c.key, /BEGIN PRIVATE KEY/);
    assert.ok(c.notAfter > Date.now() + 80 * 864e5);
    assert.equal(records.size, 0, "the challenge record is gone");
    // a second certificate reuses the account
    const accounts = st.accounts.size;
    st.finalized = false; st.challenged = false;
    await acme.issue(["*.tunnel.example.com"], dns);
    assert.equal(st.accounts.size, accounts);
  } finally { srv.close(); }
});

test("naming: older installs move to this machine; a relay alone stays a relay when asked for", () => {
  assert.deepEqual(cleanNaming({ mode: "wildcard", prefix: "tunnel", relay: "203.0.113.7" }, { saved: true }),
    { mode: "wildcard", prefix: "tunnel", certs: "self", relay: "203.0.113.7" }, "the old relay becomes the backup");
  assert.equal(cleanNaming({ mode: "wildcard", prefix: "tunnel" }, { saved: true }).certs, "auto", "Cloudflare is asked once");
  assert.equal(cleanNaming({ mode: "wildcard", prefix: "" }, { saved: true }).certs, "cloudflare");
  assert.equal(cleanNaming({ mode: "wildcard", prefix: "tunnel", relay: "203.0.113.7" }).certs, "relay", "an API call without certs means what it used to");
  assert.throws(() => cleanNaming({ mode: "wildcard", certs: "relay" }), /relay/);
});

// TunnelManager with a fake zone, and an edge whose certificate and checks are stubbed
function selfManager() {
  const tm = new TunnelManager({ dataDir: tmp("edge-tun-"), domain: { mainHost: "aegis.example.com", tunnelId: "abc-123", cert: "/dev/null" },
                                 quick: null, forbiddenPorts: [4310], log: () => {} });
  const zone = new Map(), dns = [];
  tm.cfApi = async (method, path, body) => {
    dns.push(`${method} ${path}`);
    const ty = /type=([A-Z]+)/.exec(path);
    if (method === "GET" && ty) return [...zone.values()].filter((r) => r.type === ty[1]);
    if (method === "GET") { const name = decodeURIComponent(/name=([^&]+)/.exec(path)[1]); return zone.has(name) ? [zone.get(name)] : []; }
    if (method === "POST") { const r = { id: "r" + dns.length, ...body }; zone.set(body.name, r); return r; }
    if (method === "PUT") { const r = { ...body, id: path.split("/").pop() }; zone.set(body.name, r); return r; }
    if (method === "DELETE") { for (const [k, v] of zone) if (path.endsWith("/" + v.id)) zone.delete(k); return {}; }
    return {};
  };
  tm.detectScheme = async () => "http"; tm.refreshFavicon = () => {}; tm.healthOne = () => {}; tm.dnsAnswers = async () => true;
  const e = tm.edge;
  let reachable = false;
  e.ensureCert = async () => { e.cur = { names: [`*.${e.base}`], notAfter: Date.now() + 90 * 864e5, fingerprint: "AA" }; return e.cur; };
  e.refreshIp = async () => { e.publicIp = "198.51.100.20"; return e.publicIp; };
  e.probe = async () => (reachable ? { ok: true } : { ok: false, why: "port 443 is closed there" });
  e.mapPort = async () => {};
  e.probeRelay = async () => false;
  return { tm, zone, e, setReachable: (v) => { reachable = v; } };
}
const settle = () => new Promise((r) => setTimeout(r, 20));

test("this machine holds the certificate: the wildcard goes to the backup relay until port 443 works, then here", async () => {
  const { tm, zone, e, setReachable } = selfManager();
  try {
    await tm.create({ port: 3000, sub: "radio" });
    const info = await tm.setNaming({ mode: "wildcard", prefix: "tunnel", certs: "self", relay: "203.0.113.7" });
    assert.equal(info.certs, "self");
    assert.equal(info.edge.base, "tunnel.example.com");
    let w = zone.get("*.tunnel.example.com");
    assert.deepEqual([w.type, w.content, w.proxied], ["A", "203.0.113.7", false], "not reachable yet: the relay");
    assert.equal(tm.relayAsk("radio.tunnel.example.com"), true, "the backup still gets its certificates");
    assert.ok(e.context("radio.tunnel.example.com") !== undefined);
    assert.equal(e.context("a.b.tunnel.example.com"), null, "one level only");
    assert.equal(e.context("aegis.example.com"), null, "never the dashboard");
    assert.equal(e.checkName, "edge-check-aegis.example.com", "the outside check is one level under the zone");
    assert.deepEqual(e.names(), ["*.tunnel.example.com", "edge-check-aegis.example.com"]);

    setReachable(true);
    await e.check(); await e.check(); await settle();
    w = zone.get("*.tunnel.example.com");
    assert.equal(w.content, "198.51.100.20", "reachable: straight here");
    assert.equal(tm.namingInfo().edge.via, "direct");

    setReachable(false);
    await e.check(); await e.check(); await settle();
    assert.equal(zone.get("*.tunnel.example.com").content, "198.51.100.20", "two failures are not enough to leave");
    await e.check(); await settle();
    assert.equal(zone.get("*.tunnel.example.com").content, "203.0.113.7", "three are: back to the relay");
  } finally { tm.stop(); }
});

test("this machine without a backup: the record stays here, reachable or not", async () => {
  const { tm, zone, e } = selfManager();
  try {
    await tm.create({ port: 3000 });
    await tm.setNaming({ mode: "wildcard", prefix: "tunnel", certs: "self" });
    const w = zone.get("*.tunnel.example.com");
    assert.deepEqual([w.type, w.content], ["A", "198.51.100.20"]);
    assert.equal(tm.relayAsk("3000.tunnel.example.com"), false, "no relay, no questions");
    // no certificate, nothing moves
    e.ensureCert = async () => { throw new Error("rate limited"); };
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "t2", certs: "self" }), /No certificate for \*\.t2\.example\.com: rate limited/);
    assert.equal(tm.hostFor(3000), "3000.tunnel.example.com");
    assert.equal(e.base, "tunnel.example.com", "the edge is back on the old name");
  } finally { tm.stop(); }
});

test("the PROXY header a relay puts first: v1 and v2, the bytes after it kept", async () => {
  const { parseProxyHeader, readProxyHeader } = await import("../burrow/proxyproto.mjs");
  assert.deepEqual(parseProxyHeader(Buffer.from("PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n\x16\x03")), { header: 43, src: "203.0.113.7" });
  assert.equal(parseProxyHeader(Buffer.from("PROXY TCP4 203.0")), null, "needs more");
  assert.throws(() => parseProxyHeader(Buffer.from("\x16\x03\x01\x02\x00")), /PROXY/);
  const v2 = Buffer.concat([Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c]),
                            Buffer.from([198, 51, 100, 9, 10, 0, 0, 1, 0xc3, 0x50, 0x01, 0xbb]), Buffer.from("hello")]);
  assert.deepEqual(parseProxyHeader(v2), { header: 28, src: "198.51.100.9" });
  // on a real socket, split across writes
  const { createServer, connect } = await import("node:net");
  const got = await new Promise((resolve) => {
    const srv = createServer((s) => readProxyHeader(s).then(({ src }) => {
      let rest = ""; s.on("data", (d) => { rest += d; }); s.on("end", () => { srv.close(); resolve({ src, rest }); }); s.resume();
    }));
    srv.listen(0, "127.0.0.1", () => {
      const c = connect(srv.address().port, "127.0.0.1", () => { c.write(v2.subarray(0, 10)); setTimeout(() => { c.end(v2.subarray(10)); }, 30); });
    });
  });
  assert.deepEqual(got, { src: "198.51.100.9", rest: "hello" });
});

test("the Worker front: a Custom Domain per name, removed with the tunnel; only its own key is believed", async () => {
  const { tm, zone } = selfManager();
  const f = tm.front, domains = new Map();
  tm.cf = () => ({ zone: "z1", token: "t", account: "a1" });
  f.state.token = "tok";
  f.deploy = async (label, origin) => { f.deployed = { script: `aegis-tunnels-${label}`, origin }; return f.deployed; };
  f.addDomain = async (host, script) => { domains.set(host, script); return { hostname: host }; };
  f.removeDomain = async (host) => (domains.delete(host) ? 1 : 0);
  f.certReady = async () => true;
  try {
    await tm.create({ port: 3000, sub: "radio" });
    zone.set("*.tunnel.example.com", { id: "w1", type: "A", name: "*.tunnel.example.com", content: "203.0.113.7", comment: "aegis (burrow tunnels)" });
    const info = await tm.setNaming({ mode: "wildcard", prefix: "tunnel", certs: "worker" });
    assert.equal(info.certs, "worker");
    assert.equal(info.front.script, "aegis-tunnels-aegis");
    assert.deepEqual([...domains], [["radio.tunnel.example.com", "aegis-tunnels-aegis"]]);
    assert.ok(!zone.has("*.tunnel.example.com"), "the old wildcard record (to a relay) is swept");
    await tm.create({ port: 4000 });
    assert.ok(domains.has("4000.tunnel.example.com"), "a new tunnel gets its name at once");
    await tm.update(4000, { sub: "grafana" });
    assert.ok(!domains.has("4000.tunnel.example.com") && domains.has("grafana.tunnel.example.com"), "a rename moves the domain");
    await tm.remove(4000);
    assert.ok(!domains.has("grafana.tunnel.example.com"), "removing a tunnel removes its domain");
    assert.equal(tm.relayAsk("radio.tunnel.example.com"), false);
    // what Aegis believes
    const req = (h) => ({ headers: { ...h } });
    const good = req({ "x-aegis-front-key": f.state.key, "x-aegis-front-host": "radio.tunnel.example.com", "x-aegis-front-ip": "198.51.100.4" });
    assert.deepEqual(f.claim(good, true), { host: "radio.tunnel.example.com", ip: "198.51.100.4" });
    assert.equal(good.headers["x-aegis-front-key"], undefined, "the key never goes further");
    assert.equal(f.claim(req({ "x-aegis-front-key": "nope", "x-aegis-front-host": "radio.tunnel.example.com" }), true), null, "a wrong key");
    assert.equal(f.claim(req({ "x-aegis-front-key": f.state.key, "x-aegis-front-host": "radio.tunnel.example.com" }), false), null, "not through this machine's tunnel");
    // without a credential, nothing moves
    f.state.token = null;
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "t2", certs: "worker" }), /Worker isn't ready/);
    assert.equal(tm.hostFor(3000), "radio.tunnel.example.com");
  } finally { tm.stop(); }
});
