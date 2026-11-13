// Domains on another DNS provider (added by hand): Aegis shows the records, checks
// them on public resolvers, and only then gives the zones to the relay agent, whose
// Caddy gets a certificate per name on demand after asking home.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request } from "node:http";
import { randomBytes } from "node:crypto";
import { Domains } from "../burrow/domains.mjs";
import { TunnelManager } from "../burrow/tunnels.mjs";
import { sign, verify, startAgent } from "../relay/agent.mjs";

const tmp = (p) => mkdtempSync(join(tmpdir(), p));
const managers = [];
after(() => { for (const tm of managers) tm.stop(); });

function setup({ relay } = {}) {
  const dir = tmp("aegis-manual-");
  const state = { domain: { mainHost: "aegis.example.com", tunnelId: "t-main", cert: "/nonexistent" } };
  const settings = { get: (k) => state[k], set: (p) => Object.assign(state, p) };
  const cfCalls = [];
  const dns = { answers: {} };                // name -> [ips]; a made-up name under a wildcard answers as "*.<rest>"
  const resolve = async (name) => dns.answers[name] || dns.answers["*" + name.slice(name.indexOf("."))] || [];
  const tm = new TunnelManager({ dataDir: tmp("aegis-manual-tun-"), domain: state.domain, quick: null, forbiddenPorts: [4310], log: () => {} });
  tm.cfApi = async (method, path, body) => (method === "GET" ? [] : { id: "m1", ...body });
  tm.detectScheme = async () => "http"; tm.refreshFavicon = () => {}; tm.healthOne = () => {}; tm.dnsAnswers = async () => true;
  const D = new Domains({ settings, dataDir: dir, origin: () => ({ url: "https://127.0.0.1:4301", insecure: true }), log: () => {}, bin: () => null,
    mainZone: () => "example.com", mainCert: () => null, onChange: (l) => tm.useExtras(l),
    cfApi: async (...a) => { cfCalls.push(a); throw new Error("no Cloudflare here"); }, resolve, autostart: false });
  if (relay) D.useRelay(relay);
  tm.useExtras(D.serving(), (z) => D.takenOn(z));
  managers.push(tm);
  return { D, tm, dns, cfCalls, state };
}
const fakeRelay = () => {
  const sent = [];
  return { sent, configured: () => true, host: () => "203.0.113.7", ip: async () => "203.0.113.7", outdated: () => null, version: () => "1.8.0",
           ready: async () => ({ ok: true }), push: async () => { throw new Error("no certificates for a manual domain"); }, remove: async () => {},
           manual: async (suffixes) => { sent.push(suffixes); return { ok: true, manual: suffixes, ask: "ours" }; }, ask: () => "ours" };
};

test("a domain by hand: records to make, live only once public DNS points at the VPS", async () => {
  const relay = fakeRelay();
  const { D, tm, dns, cfCalls } = setup({ relay });
  await tm.create({ port: 3000 });
  await tm.create({ port: 8096, sub: "jelly" });

  // no VPS, a dashboard name, or nothing for tunnels: refused
  const bare = setup();
  await assert.rejects(bare.D.add({ manual: true, zone: "other.net" }), /Link your VPS first/);
  await assert.rejects(D.add({ manual: true, zone: "other.net", label: "home" }), /needs Cloudflare/);
  await assert.rejects(D.add({ manual: true, zone: "example.com" }), /already the main domain/);
  await assert.rejects(D.add({ manual: true, zone: "other.net", tunnels: "none" }), /some tunnels/);

  const v = await D.add({ manual: true, zone: "Other.NET", tunnels: "all" });
  const x = v.domains[0];
  assert.equal(x.zone, "other.net");
  assert.equal(x.route, "vps");
  assert.equal(x.manual.live, null);
  assert.deepEqual(x.manual.records.map((r) => [r.type, r.name, r.value, r.ttl]), [["A", "*.other.net", "203.0.113.7", 300]]);
  assert.equal(x.cert, null, "no Let's Encrypt wildcard for it");
  assert.equal(tm.matchHost("3000.other.net"), null, "nothing answers before its records check out");
  assert.equal(D.manualAsk("3000.other.net", (h) => tm.matchHost(h)), null);
  assert.ok(D.wantsRelay());

  // the record isn't there yet, then points somewhere else: not live, the VPS isn't told
  let c = await D.checkDns("other.net");
  assert.deepEqual(c.domains[0].manual.records.map((r) => [r.ok, r.error]), [[false, "not there yet"]]);
  dns.answers["*.other.net"] = ["198.51.100.1"];
  c = await D.checkDns("other.net");
  assert.deepEqual(c.domains[0].manual.records.map((r) => [r.ok, r.error, r.got]), [[false, "points somewhere else", ["198.51.100.1"]]]);
  assert.equal(c.domains[0].manual.live, null);
  assert.deepEqual(relay.sent, []);

  // right: live, the zone goes to the agent, the names answer
  dns.answers["*.other.net"] = ["203.0.113.7"];
  c = await D.checkDns("other.net");
  assert.ok(c.domains[0].manual.live);
  assert.ok(c.domains[0].manual.records[0].ok);
  assert.deepEqual(relay.sent, [[".other.net"]]);
  assert.equal(tm.matchHost("3000.other.net"), 3000);
  assert.equal(tm.matchHost("jelly.other.net"), 8096);

  // Caddy's question (through the agent): only names that are tunnels here, and on
  const ask = (n) => { const p = D.manualAsk(n, (h) => tm.matchHost(h)); return p !== null && !!tm.get(p)?.enabled; };
  assert.equal(ask("jelly.other.net"), true);
  assert.equal(ask("nope.other.net"), false);
  assert.equal(ask("a.jelly.other.net"), false, "one level only");
  assert.equal(ask("jelly.example.com"), false, "not a domain added by hand");
  await tm.update(8096, { enabled: false });
  assert.equal(ask("jelly.other.net"), false, "a paused tunnel gets no certificate");

  // a wildcard subdomain: its own record to make, its zone to the agent at once (live already)
  c = await D.update("other.net", { subs: [{ name: "apps", wildcard: true }, { name: "blog", wildcard: false, port: 3000 }] });
  assert.deepEqual(c.domains[0].manual.records.map((r) => r.name), ["*.other.net", "*.apps.other.net", "blog.other.net"]);
  assert.deepEqual(relay.sent.at(-1), [".other.net", ".apps.other.net"]);
  await assert.rejects(D.update("other.net", { label: "home" }), /needs Cloudflare/);
  await assert.rejects(D.update("other.net", { route: "cloudflare" }), /through your VPS only/);

  // removing it: the agent lets go, nothing at the DNS provider is touched
  const r = await D.remove("other.net");
  assert.deepEqual(r.domains, []);
  assert.deepEqual(relay.sent.at(-1), []);
  assert.equal(tm.matchHost("3000.other.net"), null);
  assert.equal(cfCalls.length, 0, "Cloudflare is never asked about a domain added by hand");
});

test("records over IPv6, and a VPS that can't be reached keeps the domain waiting", async () => {
  const relay = { ...fakeRelay(), host: () => "2001:db8::7", ip: async () => "2001:db8::7" };
  const { D, dns } = setup({ relay });
  const v = await D.add({ manual: true, zone: "six.net" });
  assert.deepEqual(v.domains[0].manual.records.map((r) => [r.type, r.value]), [["AAAA", "2001:db8::7"]]);
  dns.answers["*.six.net"] = ["2001:db8::7"];
  relay.ready = async () => ({ ok: false, error: "its SSH port doesn't answer" });
  await assert.rejects(D.checkDns("six.net"), /records are right, but your VPS .* isn't reachable/);
  assert.equal(D.get("six.net").live, undefined);
  await assert.rejects(D.checkDns("nope.net"), /Only a domain added by hand/);
});

// ---------------------------------------------------------------- the agent
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const free = async () => { const s = createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; };
function get(port, path, headers = {}, method = "GET", body) {
  return new Promise((res, rej) => {
    const r = request({ host: "127.0.0.1", port, path, method, headers }, (x) => { let b = ""; x.on("data", (d) => { b += d; }); x.on("end", () => res({ status: x.statusCode, body: b })); });
    r.on("error", rej); r.end(body);
  });
}

test("agent 1.8: manual zones get on-demand sites and the ask, which asks home signed; one already there is left alone", async () => {
  const key = randomBytes(32), dir = tmp("relay-manual-");
  const caddyfile = join(dir, "Caddyfile");
  writeFileSync(caddyfile, "example.com {\n\trespond hi\n}\n");
  const asked = [];
  // home: answers the ask (signed as host "ask") for jelly.other.net only, and passes visitors
  const gate = createServer((req, res) => {
    if (req.url.startsWith("/__aegis-relay/ask?")) {
      const ok = verify(key, req.headers["x-aegis-relay"], { host: "ask", ip: "0.0.0.0", method: "GET", url: req.url });
      const name = new URL(req.url, "http://x").searchParams.get("domain");
      asked.push(name);
      res.writeHead(!ok ? 403 : name === "jelly.other.net" ? 200 : 404); return res.end();
    }
    res.end("home:" + req.headers.host);
  });
  const up = await listen(gate), ctl = await free(), hp = await free();
  const cfg = { key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: up, controlPort: ctl, httpPort: hp, mode: "caddy",
                certDir: join(dir, "certs"), caddySite: join(dir, "caddy", "aegis-relay.caddy"), caddyfile, reload: false, sshd: false };
  let agent = startAgent(cfg, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  const signed = (method, url) => ({ "x-aegis-relay": sign(key, { host: "agent", ip: "-", method, url }), "content-type": "application/json" });
  const setManual = (suffixes) => get(ctl, "/zones/manual", signed("POST", "/zones/manual"), "POST", JSON.stringify({ suffixes }));
  const askIt = (name, host = `127.0.0.1:${hp}`) => get(hp, `/__aegis_ask?domain=${name}`, { host });
  try {
    assert.equal((await get(ctl, "/zones/manual", {}, "POST", "{}")).status, 401, "unsigned: refused");
    assert.equal((await setManual([".tunnel.example.com"])).status, 400, "the first zone can't be one");
    assert.equal((await get(hp, "/", { host: "jelly.other.net", "x-aegis-client": "203.0.113.9" })).status, 421, "not a zone yet");

    let r = await setManual([".other.net", ".apps.other.net"]);
    assert.equal(r.status, 200, r.body);
    assert.deepEqual(JSON.parse(r.body), { ok: true, manual: [".other.net", ".apps.other.net"], ask: "ours" });
    const site = readFileSync(cfg.caddySite, "utf8");
    assert.match(site, /^\*\.other\.net \{\n\ttls \{\n\t\ton_demand\n\t\tprotocols tls1\.3/m, "a certificate per name, on demand");
    assert.match(site, /^\*\.apps\.other\.net \{/m);
    const cf = readFileSync(caddyfile, "utf8");
    assert.match(cf, new RegExp(`^\\{\\n\\t# aegis relay: .*\\n\\ton_demand_tls \\{\\n\\t\\task http://127\\.0\\.0\\.1:${hp}/__aegis_ask\\n\\t\\}\\n\\}\\n`), "the ask, in new global options");
    assert.match(cf, /example\.com \{\n\trespond hi\n\}/, "the rest of the Caddyfile as it was");
    assert.deepEqual(JSON.parse(readFileSync(join(dir, "manual.json"), "utf8")), [".other.net", ".apps.other.net"]);

    // visitors on those names go home, like any zone's
    r = await get(hp, "/", { host: "jelly.other.net", "x-aegis-client": "203.0.113.9" });
    assert.equal(r.body, "home:jelly.other.net");
    assert.equal((await get(hp, "/", { host: "a.b.other.net", "x-aegis-client": "203.0.113.9" })).status, 421, "one level only");

    // the ask: loopback, the listener's own name, a manual zone, and home's yes
    assert.equal((await askIt("jelly.other.net")).status, 200);
    assert.equal((await askIt("nope.other.net")).status, 404);
    assert.equal((await askIt("x.tunnel.example.com")).status, 404, "a zone with a certificate from home: not asked");
    assert.equal((await askIt("jelly.other.net", "jelly.other.net")).status, 421, "through a tunnel name it's just a visitor's path");
    assert.deepEqual(asked, ["jelly.other.net", "nope.other.net"], "only manual names go home, each once (kept a minute)");
    assert.equal((await askIt("jelly.other.net")).status, 200);
    assert.equal(asked.length, 2);
    const st = JSON.parse((await get(ctl, "/status", signed("GET", "/status"))).body);
    assert.deepEqual([st.manual, st.ask, st.features.includes("manual"), st.version], [[".other.net", ".apps.other.net"], "ours", true, "1.8.0"]);

    // a restart keeps them; the last one gone takes the ask out again
    agent.close(); await new Promise((r) => setTimeout(r, 50));
    agent = startAgent(cfg, { log: () => {} }); await new Promise((r) => setTimeout(r, 100));
    assert.equal((await get(hp, "/", { host: "jelly.apps.other.net", "x-aegis-client": "203.0.113.9" })).status, 200);
    r = await setManual([]);
    assert.deepEqual(JSON.parse(r.body), { ok: true, manual: [], ask: null });
    assert.equal(readFileSync(caddyfile, "utf8"), "example.com {\n\trespond hi\n}\n\nimport " + cfg.caddySite + "\n", "back to how it was (plus our import)");
    assert.doesNotMatch(readFileSync(cfg.caddySite, "utf8"), /other\.net/);
  } finally { agent.close(); gate.close(); }

  // a Caddyfile that has an ask of its own: left alone, reported; global options of its own: ours goes in them
  const dir2 = tmp("relay-manual-");
  const cf2 = join(dir2, "Caddyfile");
  writeFileSync(cf2, "{\n\ton_demand_tls {\n\t\task http://127.0.0.1:18440/__ask\n\t}\n}\n");
  const ctl2 = await free(), hp2 = await free();
  const a2 = startAgent({ ...cfg, controlPort: ctl2, httpPort: hp2, certDir: join(dir2, "certs"), caddySite: join(dir2, "caddy", "s.caddy"), caddyfile: cf2 }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  try {
    const r = await get(ctl2, "/zones/manual", { "x-aegis-relay": sign(key, { host: "agent", ip: "-", method: "POST", url: "/zones/manual" }) }, "POST", JSON.stringify({ suffixes: [".other.net"] }));
    assert.equal(JSON.parse(r.body).ask, "theirs http://127.0.0.1:18440/__ask");
    assert.match(readFileSync(cf2, "utf8"), /^\{\n\ton_demand_tls \{\n\t\task http:\/\/127\.0\.0\.1:18440\/__ask\n\t\}\n\}\n/, "their ask untouched");
    assert.doesNotMatch(readFileSync(cf2, "utf8"), /aegis relay: asks/);
  } finally { a2.close(); }
  const dir3 = tmp("relay-manual-"), cf3 = join(dir3, "Caddyfile");
  writeFileSync(cf3, "# my server\n{\n\temail me@example.com\n}\n");
  const ctl3 = await free(), hp3 = await free();
  const a3 = startAgent({ ...cfg, controlPort: ctl3, httpPort: hp3, certDir: join(dir3, "certs"), caddySite: join(dir3, "caddy", "s.caddy"), caddyfile: cf3 }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  try {
    await get(ctl3, "/zones/manual", { "x-aegis-relay": sign(key, { host: "agent", ip: "-", method: "POST", url: "/zones/manual" }) }, "POST", JSON.stringify({ suffixes: [".other.net"] }));
    assert.match(readFileSync(cf3, "utf8"), new RegExp(`^# my server\\n\\{\\n\\t# aegis relay: .*\\n\\ton_demand_tls \\{\\n\\t\\task http://127\\.0\\.0\\.1:${hp3}/__aegis_ask\\n\\t\\}\\n\\temail me@example\\.com\\n\\}`));
  } finally { a3.close(); }
});

test("agent 1.8: a relay that answers TLS itself refuses manual zones", async () => {
  const key = randomBytes(32), dir = tmp("relay-manual-tls-"), ctl = await free();
  const agent = startAgent({ key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: 1, controlPort: ctl, tlsPort: await free(), mode: "tls",
                             certDir: join(dir, "certs"), sshd: false }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  try {
    const r = await get(ctl, "/zones/manual", { "x-aegis-relay": sign(key, { host: "agent", ip: "-", method: "POST", url: "/zones/manual" }) }, "POST", JSON.stringify({ suffixes: [".other.net"] }));
    assert.equal(r.status, 400);
    assert.match(r.body, /need Caddy/);
    assert.ok(!existsSync(join(dir, "manual.json")));
  } finally { agent.close(); }
});
