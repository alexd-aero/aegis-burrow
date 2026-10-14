// Aegis Relay: only your Aegis and your relay agent understand each other.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request } from "node:http";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { sign, verify, startAgent } from "../relay/agent.mjs";
import { RelayLink } from "../burrow/relaylink.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "relay-test-"));
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const free = async () => { const s = createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; };
function get(port, path, headers = {}, method = "GET", body) {
  return new Promise((res, rej) => {
    const r = request({ host: "127.0.0.1", port, path, method, headers }, (x) => { let b = ""; x.on("data", (d) => { b += d; }); x.on("end", () => res({ status: x.statusCode, body: b })); });
    r.on("error", rej); r.end(body);
  });
}

test("signatures: right key, right request, once, recently", () => {
  const key = randomBytes(32), other = randomBytes(32);
  const req = { host: "radio.tunnel.example.com", ip: "203.0.113.9", method: "GET", url: "/a?b=1" };
  const h = sign(key, req);
  assert.equal(verify(key, h, req), true);
  assert.equal(verify(key, h, req), false, "a replay is refused");
  assert.equal(verify(other, sign(key, req), req), false, "another key");
  assert.equal(verify(key, sign(key, req), { ...req, ip: "198.51.100.1" }), false, "another visitor");
  assert.equal(verify(key, sign(key, req), { ...req, host: "x.tunnel.example.com" }), false, "another host");
  assert.equal(verify(key, sign(key, req), { ...req, url: "/admin" }), false, "another path");
  assert.equal(verify(key, sign(key, { ...req, ts: Date.now() - 120e3 }), req), false, "too old");
  assert.equal(verify(key, "garbage", req), false);
});

test("the agent: signed to the gate with the visitor's address, foreign names and forged headers refused", async () => {
  const key = randomBytes(32);
  let seen = null;
  const gate = createServer((req, res) => {
    const ip = req.headers["x-aegis-relay-ip"];
    const ok = verify(key, req.headers["x-aegis-relay"], { host: req.headers.host, ip, method: req.method, url: req.url });
    seen = { ok, ip, host: req.headers.host, url: req.url, xff: req.headers["x-forwarded-for"], cf: req.headers["cf-connecting-ip"] };
    res.writeHead(ok ? 200 : 403); res.end(ok ? "hello from home" : "no");
  });
  const upstreamPort = await listen(gate);
  const dir = tmp();
  const agent = startAgent({ key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort, controlPort: await free(), httpPort: await free(),
                             mode: "caddy", certDir: join(dir, "certs"), caddySite: join(dir, "caddy", "aegis-relay.caddy"), replaces: join(dir, "old.caddy"), reload: false }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  const hp = agent.front.address().port;
  try {
    let r = await get(hp, "/x?y=1", { host: "radio.tunnel.example.com", "x-aegis-client": "203.0.113.9", "x-aegis-relay-ip": "1.2.3.4", "cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "1.2.3.4" });
    assert.equal(r.status, 200); assert.equal(r.body, "hello from home");
    assert.deepEqual(seen, { ok: true, ip: "203.0.113.9", host: "radio.tunnel.example.com", url: "/x?y=1", xff: undefined, cf: undefined }, "Caddy's word for the visitor, nothing the visitor claimed");
    r = await get(hp, "/", { host: "evil.example.org", "x-aegis-client": "203.0.113.9" });
    assert.equal(r.status, 421, "only names under the tunnel zone");
    r = await get(hp, "/", { host: "a.b.tunnel.example.com", "x-aegis-client": "203.0.113.9" });
    assert.equal(r.status, 421, "one level only");
    gate.close();
    r = await get(hp, "/", { host: "radio.tunnel.example.com", "x-aegis-client": "203.0.113.9" });
    assert.equal(r.status, 502, "home not connected: a page saying so");
    assert.match(r.body, /home end isn't connected/);
  } finally { agent.close(); gate.close(); }
});

test("the agent's control: only your Aegis may hand it a certificate; Caddy gets its site", async () => {
  const key = randomBytes(32), dir = tmp();
  writeFileSync(join(dir, "old.caddy"), "*.tunnel.example.com { }\n");
  const ctl = await free();
  const agent = startAgent({ key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: 1, controlPort: ctl, httpPort: await free(),
                             mode: "caddy", certDir: join(dir, "certs"), caddySite: join(dir, "caddy", "aegis-relay.caddy"), replaces: join(dir, "old.caddy"), reload: false }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  const signed = (method, url) => ({ "x-aegis-relay": sign(key, { host: "agent", ip: "-", method, url }), "content-type": "application/json" });
  try {
    const mk = (cn, san) => {
      execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", `/CN=${cn}`,
                               "-addext", `subjectAltName=${san}`, "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
      return JSON.stringify({ cert: readFileSync(join(dir, "c.pem"), "utf8"), key: readFileSync(join(dir, "k.pem"), "utf8") });
    };
    let r = await get(ctl, "/status");
    assert.equal(r.status, 401, "unsigned: refused");
    r = await get(ctl, "/cert", { "x-aegis-relay": sign(randomBytes(32), { host: "agent", ip: "-", method: "POST", url: "/cert" }) }, "POST", mk("x", "DNS:*.tunnel.example.com"));
    assert.equal(r.status, 401, "another key: refused");
    r = await get(ctl, "/cert", signed("POST", "/cert"), "POST", mk("x", "DNS:*.other.example.com"));
    assert.equal(r.status, 400, "a certificate for other names: refused");
    r = await get(ctl, "/cert", signed("POST", "/cert"), "POST", mk("x", "DNS:*.tunnel.example.com,DNS:edge-check.example.com"));
    assert.equal(r.status, 200, r.body);
    assert.ok(existsSync(join(dir, "certs", "tunnel.key")));
    const site = readFileSync(join(dir, "caddy", "aegis-relay.caddy"), "utf8");
    assert.match(site, /\*\.tunnel\.example\.com \{/); assert.match(site, /header_up X-Aegis-Client \{remote_host\}/);
    assert.ok(!existsSync(join(dir, "old.caddy")) && existsSync(join(dir, "old.caddy.before-aegis-relay")), "the hand-made site moved aside");
    r = await get(ctl, "/status", signed("GET", "/status"));
    assert.equal(JSON.parse(r.body).cert.names, "DNS:*.tunnel.example.com, DNS:edge-check.example.com");
  } finally { agent.close(); }
});

test("agent 1.1: more zones, each with its own certificate and Caddy site; a signed update takes its place", async () => {
  const key = randomBytes(32), dir = tmp();
  let seen = null;
  const gate = createServer((req, res) => { seen = req.headers.host; res.end("ok"); });
  const up = await listen(gate), ctl = await free(), hp = await free();
  const agentFile = join(dir, "agent.mjs");
  writeFileSync(agentFile, "// old agent\n");
  const cfg = { key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: up, controlPort: ctl, httpPort: hp,
                mode: "caddy", certDir: join(dir, "certs"), caddySite: join(dir, "caddy", "aegis-relay.caddy"), reload: false, agentFile, exitOnUpdate: false };
  let agent = startAgent(cfg, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  const signed = (method, url) => ({ "x-aegis-relay": sign(key, { host: "agent", ip: "-", method, url }), "content-type": "application/json" });
  const mk = (san, extra = {}) => {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=x",
                             "-addext", `subjectAltName=${san}`, "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
    return JSON.stringify({ cert: readFileSync(join(dir, "c.pem"), "utf8"), key: readFileSync(join(dir, "k.pem"), "utf8"), ...extra });
  };
  const visit = (host) => get(hp, "/", { host, "x-aegis-client": "203.0.113.9" });
  try {
    assert.equal((await visit("a.other.net")).status, 421, "not a zone yet");
    let r = await get(ctl, "/cert", signed("POST", "/cert"), "POST", mk("DNS:*.tunnel.example.com", { suffix: ".other.net" }));
    assert.equal(r.status, 400, "a zone's certificate must be for that zone");
    assert.equal((await get(ctl, "/cert", signed("POST", "/cert"), "POST", mk("DNS:*.tunnel.example.com"))).status, 200);
    r = await get(ctl, "/cert", signed("POST", "/cert"), "POST", mk("DNS:*.other.net", { suffix: ".other.net" }));
    assert.equal(r.status, 200, r.body);
    assert.ok(existsSync(join(dir, "certs", "z.other.net.crt")));
    assert.deepEqual(JSON.parse(readFileSync(join(dir, "zones.json"), "utf8")), [".other.net"]);
    const site = readFileSync(join(dir, "caddy", "aegis-relay.caddy"), "utf8");
    assert.match(site, /^\*\.tunnel\.example\.com \{/m); assert.match(site, /^\*\.other\.net \{\n\ttls .*z\.other\.net\.crt/m);
    r = await visit("a.other.net"); assert.equal(r.status, 200); assert.equal(seen, "a.other.net");
    assert.equal((await visit("a.b.other.net")).status, 421, "one level only");
    const st = JSON.parse((await get(ctl, "/status", signed("GET", "/status"))).body);
    assert.deepEqual(st.zones.map((z) => [z.suffix, z.cert.names]), [[".tunnel.example.com", "DNS:*.tunnel.example.com"], [".other.net", "DNS:*.other.net"]]);
    assert.ok(st.features.includes("zones") && st.features.includes("update"));

    // a restart keeps the zones
    agent.close(); await new Promise((r) => setTimeout(r, 50));
    agent = startAgent(cfg, { log: () => {} }); await new Promise((r) => setTimeout(r, 100));
    assert.equal((await visit("b.other.net")).status, 200);
    r = await get(ctl, "/zones/remove", signed("POST", "/zones/remove"), "POST", JSON.stringify({ suffix: ".tunnel.example.com" }));
    assert.equal(r.status, 400, "the first zone stays");
    r = await get(ctl, "/zones/remove", signed("POST", "/zones/remove"), "POST", JSON.stringify({ suffix: ".other.net" }));
    assert.equal(r.status, 200);
    assert.equal((await visit("b.other.net")).status, 421);
    assert.doesNotMatch(readFileSync(join(dir, "caddy", "aegis-relay.caddy"), "utf8"), /other\.net/);

    // updates: only signed, only an agent that parses
    assert.equal((await get(ctl, "/update", {}, "POST", JSON.stringify({ code: "x" }))).status, 401);
    r = await get(ctl, "/update", signed("POST", "/update"), "POST", JSON.stringify({ code: "export function startAgent( {", version: "9" }));
    assert.equal(r.status, 400); assert.match(r.body, /doesn't parse/);
    assert.equal(readFileSync(agentFile, "utf8"), "// old agent\n");
    r = await get(ctl, "/update", signed("POST", "/update"), "POST", JSON.stringify({ code: "export function startAgent() {}\n", version: "9.9.9" }));
    assert.equal(r.status, 200, r.body);
    assert.equal(readFileSync(agentFile, "utf8"), "export function startAgent() {}\n");
    assert.equal(readFileSync(agentFile + ".prev", "utf8"), "// old agent\n");
  } finally { agent.close(); gate.close(); }
});

test("setup: a one-time link, a script that locks the user down, registration pins the host key", () => {
  const link = new RelayLink({ dataDir: tmp(), log: () => {} });
  assert.throws(() => link.setup({ host: "not a host" }), /IP address or host name/);
  assert.throws(() => link.setup({ host: "192.0.2.10" }), /tunnel names/);
  const s = link.setup({ host: "192.0.2.10", suffix: ".tunnel.example.com" });
  assert.equal(link.script("wrong", { base: "https://aegis.example.com" }), null);
  const sc = link.script(s.token, { base: "https://aegis.example.com" });
  assert.ok(sc.includes('"suffix":".tunnel.example.com"'), "the names it was made for");
  assert.match(sc, /trap .* EXIT/, "a failure says where it stopped");
  assert.match(sc, /Linked\./, "and success says the link was checked");
  assert.match(sc, /restrict,port-forwarding,permitlisten="127\.0\.0\.1:18452",permitopen="127\.0\.0\.1:18451" ssh-ed25519 /);
  assert.match(sc, /AEGIS_RELAY_AGENT'\n\/\/ Aegis Relay agent/);
  assert.ok(sc.includes(`/__gate/relay/register?t=${s.token}`));
  assert.ok(sc.includes(link.state.key), "the key goes only into this script");
  const f = join(tmp(), "install.sh"); writeFileSync(f, sc);
  execFileSync("bash", ["-n", f]);                                   // it parses
  assert.throws(() => link.register(s.token, { hostKey: "nonsense" }), /host key/);
  link.register(s.token, { hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBtc2pHXhJvGqvHn3pJcNQ8YlJmT1gWqvFfKhXJb0y1 root@vps", version: "1.0.0", mode: "caddy" });
  assert.ok(link.configured());
  assert.match(readFileSync(link.knownHosts, "utf8"), /^192\.0\.2\.10 ssh-ed25519 AAAAC3/);
  assert.throws(() => link.register(s.token, { hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBtc2pHXhJvGqvHn3pJcNQ8YlJmT1gWqvFfKhXJb0y1" }), /expired/, "used once");
  // a request from the agent is accepted, anything else isn't
  const ok = { headers: { "x-aegis-relay-ip": "203.0.113.9", "x-aegis-relay": sign(link.keyBuf(), { host: "a.tunnel.example.com", ip: "203.0.113.9", method: "GET", url: "/" }) }, method: "GET", url: "/" };
  assert.equal(link.verifyRequest(ok, "a.tunnel.example.com"), "203.0.113.9");
  assert.equal(link.verifyRequest({ ...ok, headers: { "x-aegis-relay-ip": "203.0.113.9" } }, "a.tunnel.example.com"), null);
  link.forget();
  assert.equal(link.configured(), false);
});

test("Caddy with sites imported by name: the old import line becomes the agent's, a missing one is added", async () => {
  const key = randomBytes(32), dir = tmp();
  const sites = join(dir, "sites"), cf = join(dir, "Caddyfile");
  execFileSync("mkdir", ["-p", sites]);
  writeFileSync(join(sites, "aegis-tunnels.caddy"), "*.tunnel.example.com { }\n");
  writeFileSync(cf, `{\n}\nimport ${sites}/console.caddy\nimport ${sites}/aegis-tunnels.caddy\n`);
  const agent = startAgent({ key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: 1, controlPort: await free(), httpPort: await free(), mode: "caddy",
                             certDir: join(dir, "certs"), caddySite: join(sites, "aegis-relay.caddy"), replaces: join(sites, "aegis-tunnels.caddy"), caddyfile: cf, reload: false }, { log: () => {} });
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=x",
                             "-addext", "subjectAltName=DNS:*.tunnel.example.com", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
    agent.installCert(readFileSync(join(dir, "c.pem"), "utf8"), readFileSync(join(dir, "k.pem"), "utf8"));
    const text = readFileSync(cf, "utf8");
    assert.ok(text.includes(`import ${sites}/aegis-relay.caddy`), text);
    assert.ok(!text.includes("aegis-tunnels.caddy"), "the old site's import line is gone");
    assert.equal(text.match(/aegis-relay\.caddy/g).length, 1, "imported once");
    // a Caddyfile with a glob over the folder is left alone
    writeFileSync(cf, `import ${sites}/*\n`);
    agent.installCert(readFileSync(join(dir, "c.pem"), "utf8"), readFileSync(join(dir, "k.pem"), "utf8"));
    assert.equal(readFileSync(cf, "utf8"), `import ${sites}/*\n`);
  } finally { agent.close(); }
});
