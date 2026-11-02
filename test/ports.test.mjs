// A tunnel on another port of an address (name:8080): how it's named and found,
// and the relay agent answering that port without touching anything else.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { sign, verify, startAgent } from "../relay/agent.mjs";
import { TunnelManager } from "../burrow/tunnels.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "ports-test-"));
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const free = async () => { const s = createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; };

function manager(certs = "self") {
  const tm = new TunnelManager({ dataDir: tmp(), domain: { mainHost: "dash.example.com", tunnelId: "t-1", cert: "/nonexistent" }, quick: null, forbiddenPorts: [4301], log: () => {},
                                 naming: { mode: "wildcard", prefix: "tunnel", certs: "worker" } });
  tm.naming = { ...tm.naming, certs, route: "vps", relay: "192.0.2.1" };
  tm.cfApi = async (method, path, body) => (method === "GET" ? [] : { id: "r1", ...body });
  tm.ensureWildcard = async () => ({ id: "w", name: "*.tunnel.example.com", ready: true });
  tm.detectScheme = async () => "http"; tm.refreshFavicon = () => {}; tm.healthOne = () => {}; tm.dnsAnswers = async () => true;
  return tm;
}

test("a port on an address: its name follows its parent's, and it isn't reachable any other way", async () => {
  const tm = manager();
  try {
    await tm.create({ port: 5001, sub: "nex2", app: "pages" });
    const c = await tm.create({ port: 5002, parent: 5001, publicPort: 8080, app: "pages" });
    assert.equal(tm.hostFor(5002), "nex2.tunnel.example.com:8080");
    assert.equal(c.url, "https://nex2.tunnel.example.com:8080");
    assert.equal(c.parent, 5001); assert.equal(c.publicPort, 8080);
    assert.equal(tm.matchHost("nex2.tunnel.example.com"), 5001, "the name is its parent's");
    assert.equal(tm.matchHost("5002.tunnel.example.com"), null, "and it has no name of its own");
    assert.equal(tm.portChild(5001, 8080), 5002);
    assert.equal(tm.portChild(5001, 9090), null);
    assert.deepEqual(tm.publicPorts(), [8080]);
    assert.deepEqual(tm.portsSupport(), { ok: true, via: "relay" });

    await assert.rejects(tm.create({ port: 5003, parent: 5001, publicPort: 8080, app: "pages" }), /already has port 8080/);
    await assert.rejects(tm.create({ port: 5003, parent: 5001, publicPort: 80, app: "pages" }), /1024 to 65535/);
    await assert.rejects(tm.create({ port: 5003, parent: 5001, publicPort: 6667, app: "pages" }), /Browsers refuse/);
    await assert.rejects(tm.create({ port: 5003, parent: 5001, publicPort: 4301, app: "pages" }), /Aegis's own/);
    await assert.rejects(tm.create({ port: 5003, parent: 5002, publicPort: 9000, app: "pages" }), /not on another port/);
    await assert.rejects(tm.create({ port: 5003, parent: 5001, publicPort: 9000, app: "other" }), /belongs to something else/);

    await tm.update(5002, { enabled: false });
    assert.deepEqual(tm.publicPorts(), [], "paused: nothing needs to answer");
    await tm.update(5002, { enabled: true, publicPort: 9443 });
    assert.equal(tm.hostFor(5002), "nex2.tunnel.example.com:9443");

    await tm.remove(5001);
    assert.equal(tm.get(5002), undefined, "the ports go with their address");
  } finally { tm.stop?.(); }
});

test("through Cloudflare's certificates a port can't answer, and it says so", async () => {
  const tm = manager("worker");
  try {
    assert.equal(tm.portsSupport().ok, false);
    tm.naming.certs = "self";
    await tm.create({ port: 5001, sub: "a" });
    tm.naming.certs = "cloudflare";
    await assert.rejects(tm.create({ port: 5002, parent: 5001, publicPort: 8080 }), /wildcard certificate/);
  } finally { tm.stop?.(); }
});

test("the agent: a port of its own, TLS, signed with the port; what's in use stays untouched", async () => {
  const key = randomBytes(32);
  const seen = [];
  const gate = createServer((req, res) => {
    const ip = req.headers["x-aegis-relay-ip"];
    seen.push({ ok: verify(key, req.headers["x-aegis-relay"], { host: req.headers.host, ip, method: req.method, url: req.url }), ip, host: req.headers.host });
    res.writeHead(200); res.end("home");
  });
  const upstreamPort = await listen(gate), dir = tmp();
  const cert = join(dir, "c.pem"), pk = join(dir, "k.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=x", "-addext", "subjectAltName=DNS:*.tunnel.example.com", "-keyout", pk, "-out", cert], { stdio: "ignore" });
  const ctl = await free();
  const agent = startAgent({ key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort, controlPort: ctl, httpPort: await free(),
                             mode: "caddy", certDir: join(dir, "certs"), caddySite: join(dir, "caddy", "aegis-relay.caddy"), replaces: join(dir, "old.caddy"), reload: false, firewall: false }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  agent.installCert(readFileSync(cert, "utf8"), readFileSync(pk, "utf8"));
  const post = (url, body) => new Promise((ok, no) => {
    const b = JSON.stringify(body);
    const r = httpRequest({ host: "127.0.0.1", port: ctl, method: "POST", path: url, agent: false, headers: { "x-aegis-relay": sign(key, { host: "agent", ip: "-", method: "POST", url }), "content-length": Buffer.byteLength(b) } }, (res) => { let d = ""; res.on("data", (x) => { d += x; }); res.on("end", () => ok({ status: res.statusCode, json: JSON.parse(d || "{}") })); });
    r.on("error", no); r.end(b);
  });
  const visit = (port, host) => new Promise((ok, no) => {
    const r = httpsRequest({ host: "127.0.0.1", port, servername: "nex2.tunnel.example.com", rejectUnauthorized: false, agent: false, path: "/x", headers: { host, connection: "close", "x-aegis-client": "9.9.9.9" } }, (res) => { let d = ""; res.on("data", (x) => { d += x; }); res.on("end", () => ok({ status: res.statusCode, body: d, san: res.socket.getPeerCertificate?.().subjectaltname })); });
    r.on("error", no); r.end();
  });
  const busy = createServer(), busyPort = await new Promise((r) => busy.listen(0, "0.0.0.0", () => r(busy.address().port)));
  const p = await free();
  try {
    let r = await post("/ports", { ports: [p, busyPort, upstreamPort] });
    assert.equal(r.status, 200);
    assert.equal(r.json.ports[p].state, "listening");
    assert.match(r.json.ports[busyPort].error, /Something else on this server uses/, "somebody else's port stays theirs");
    assert.match(r.json.ports[upstreamPort].error, /relay's own/);
    assert.equal(busy.listening, true);

    const v = await visit(p, "nex2.tunnel.example.com:9999");
    assert.equal(v.body, "home");
    assert.match(v.san, /\*\.tunnel\.example\.com/, "the wildcard certificate");
    const s = seen.at(-1);
    assert.equal(s.ok, true, "signed");
    assert.equal(s.host, `nex2.tunnel.example.com:${p}`, "the port it came in on, not the one Host claims");
    assert.equal(s.ip, "127.0.0.1", "the visitor is who connected: no Caddy in front here, so x-aegis-client means nothing");

    assert.equal((await visit(p, "evil.example.org")).status, 421, "only our names");

    r = await post("/ports", { ports: [] });
    assert.deepEqual(r.json.ports, {});
    await assert.rejects(visit(p, "nex2.tunnel.example.com"), /ECONNREFUSED|ECONNRESET|socket hang up/, "closed again");
    assert.deepEqual(JSON.parse(readFileSync(join(dir, "ports.json"), "utf8")), [], "and remembered across restarts");
    const unsigned = await new Promise((ok) => { const q = httpRequest({ host: "127.0.0.1", port: ctl, method: "POST", path: "/ports", agent: false }, (res) => { res.resume(); ok(res.statusCode); }); q.end("{}"); });
    assert.equal(unsigned, 401);
  } finally { agent.close(); gate.close(); gate.closeAllConnections(); busy.close(); }
});
