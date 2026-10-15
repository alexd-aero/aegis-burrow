// More domains (burrow/domains.mjs): another zone's dashboard name and tunnel names, beside the main domain.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Domains } from "../burrow/domains.mjs";
import { TunnelManager } from "../burrow/tunnels.mjs";

const pem = (zoneID) => `-----BEGIN ARGO TUNNEL TOKEN-----\n${Buffer.from(JSON.stringify({ zoneID, accountID: "acc", apiToken: "tok-" + zoneID })).toString("base64")}\n-----END ARGO TUNNEL TOKEN-----\n`;

const managers = [];
after(() => { for (const tm of managers) tm.stop(); });
function setup(records = [], { relay, reaches = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "aegis-dom-"));
  writeFileSync(join(dir, "main.pem"), pem("z1"));
  const state = { domain: { mainHost: "aegis.example.com", tunnelId: "t-main", cert: join(dir, "main.pem") } };
  const settings = { get: (k) => state[k], set: (p) => Object.assign(state, p) };
  const recs = [...records], calls = [];
  // Cloudflare, faked: one zone's records
  const cfApi = async (token, method, path, body) => {
    calls.push(`${method} ${path.replace(/^\/zones\/[^/]+/, "")}`);
    if (/^\/zones\/[^/]+$/.test(path)) return { name: { z2: "other.net", z1: "example.com" }[path.split("/")[2]] };
    // which zones a token can see: tok-z1 (the main domain's) sees example.com, plus `reaches`
    const zn = /^\/zones\?name=(.+)$/.exec(path);
    if (zn) { const name = decodeURIComponent(zn[1]); return (reaches[token] || []).includes(name) ? [{ id: "z2", name, account: { id: "acc" } }] : []; }
    const id = /dns_records\/([^/?]+)/.exec(path)?.[1];
    if (method === "GET") { const n = /name=([^&]+)/.exec(path); return n ? recs.filter((r) => r.name === decodeURIComponent(n[1])) : recs; }
    if (method === "POST") { const r = { id: "r" + calls.length, ...body }; recs.push(r); return r; }
    if (method === "PUT") { const i = recs.findIndex((r) => r.id === id); recs[i] = { id, ...body }; return recs[i]; }
    if (method === "DELETE") { recs.splice(recs.findIndex((r) => r.id === id), 1); return {}; }
  };
  const ran = [];
  const run = async (bin, args) => { ran.push(args.find((a) => ["create", "delete", "cleanup"].includes(a)) || args[0]); return { code: 0, out: args.includes("create") ? "Created tunnel x with id 11111111-2222-3333-4444-555555555555" : "", err: "" }; };
  // Let's Encrypt, faked: a real (self-signed) certificate for the names, after the TXT record went up
  const acme = { directoryUrl: "test", issued: [], async issue(names, dns) {
    const id = await dns.set(`_acme-challenge.${names[0].slice(2)}`, "v"); await dns.remove(id);
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "90", "-subj", "/CN=x",
      "-addext", `subjectAltName=${names.map((n) => "DNS:" + n).join(",")}`, "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
    this.issued.push(names[0]);
    return { key: readFileSync(join(dir, "k.pem"), "utf8"), cert: readFileSync(join(dir, "c.pem"), "utf8"), notAfter: Date.now() + 90 * 864e5 };
  } };
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "aegis-dom-tun-")), domain: state.domain, quick: null, forbiddenPorts: [4310], log: () => {} });
  const D = new Domains({ settings, dataDir: dir, origin: () => ({ url: "https://127.0.0.1:4301", insecure: true }), log: () => {},
    bin: () => "/bin/true", mainZone: () => "example.com", mainCert: () => state.domain.cert, onChange: (l) => tm.useExtras(l), cfApi, run, acme, txtVisible: async () => true, autostart: false });
  if (relay) D.useRelay(relay);
  tm.useExtras(D.list(), (z) => D.takenOn(z));
  tm.cfApi = async (method, path, body) => (method === "GET" ? [] : { id: "m1", ...body });
  tm.dnsAnswers = async () => true;
  managers.push(tm);
  // what `cloudflared tunnel login` would leave behind
  const authorize = async (zone = "z2") => { const f = join(dir, "got.pem"); writeFileSync(f, pem(zone)); await D.takeCert(f); };
  return { D, tm, recs, calls, state, authorize, ran, acme };
}

test("another domain: its own authorization, the dashboard there, a wildcard for tunnels", async () => {
  const { D, tm, recs, authorize } = setup([{ id: "mx", name: "other.net", type: "MX", content: "mail.other.net" }, { id: "w", name: "www.other.net", type: "A", content: "203.0.113.4" }]);
  await assert.rejects(D.add({ label: "aegis" }), /which domain first/);
  await assert.rejects(authorize("z1"), /already the main domain/);
  await authorize();
  assert.deepEqual(D.view().pending, { zone: "other.net", via: "login" });
  const v = await D.add({ label: "home", tunnels: "all" });
  assert.equal(v.domains[0].dashboard, "home.other.net");
  assert.equal(v.pending, null);
  assert.deepEqual(recs.filter((r) => r.type === "CNAME").map((r) => [r.name, r.content, r.proxied]).sort(),
    [["*.other.net", "11111111-2222-3333-4444-555555555555.cfargotunnel.com", true], ["home.other.net", "11111111-2222-3333-4444-555555555555.cfargotunnel.com", true]]);
  assert.ok(D.isDashboard("home.other.net") && D.isDashboard("HOME.other.net:443"));
  assert.equal(D.isDashboard("aegis.other.net"), false);
  assert.match(D.writeConfig(D.get("other.net")), /cloudflared\.yml$/);
  await assert.rejects((async () => { await authorize(); })(), /already added/);

  // tunnels there: <sub|PORT>.other.net
  await tm.create({ port: 3000 });
  await tm.create({ port: 8096, sub: "jelly" });
  assert.equal(tm.matchHost("3000.other.net"), 3000);
  assert.equal(tm.matchHost("jelly.other.net"), 8096);
  assert.equal(tm.matchHost("8096.other.net"), null, "a tunnel with a name of its own is only reached by it");
  assert.equal(tm.matchHost("home.other.net"), null, "the dashboard's name");
  assert.equal(tm.matchHost("a.b.other.net"), null);
  assert.equal(tm.matchHost("tunnel-3000-aegis.example.com"), 3000, "the main domain's names still work");
  assert.deepEqual(tm.get(3000) && tm.summary(tm.get(3000)).also.map((a) => a.url), ["https://3000.other.net"]);
  await D.refreshTaken(D.get("other.net"), true);
  await tm.update(8096, { sub: "www" });
  assert.match(tm.summary(tm.get(8096)).also[0].hidden, /record of its own/, "www.other.net has an A record, which wins over the wildcard");
});

test("picked tunnels only, the dashboard only, and removing a domain takes only its own records", async () => {
  const { D, tm, recs, authorize } = setup([{ id: "mx", name: "other.net", type: "MX", content: "mail.other.net" }]);
  await authorize();
  await D.add({ label: "", tunnels: "picked" });
  assert.equal(D.isDashboard("aegis.other.net"), false);
  assert.deepEqual(recs.filter((r) => r.type === "CNAME").map((r) => r.name), ["*.other.net"], "no dashboard: no record for it");
  await tm.create({ port: 3000 });
  await tm.create({ port: 4000 });
  assert.equal(tm.matchHost("3000.other.net"), null, "not picked");
  await tm.update(3000, { domains: ["other.net", "nope.org"] });
  assert.deepEqual(tm.get(3000).domains, ["other.net"], "only domains that exist");
  assert.equal(tm.matchHost("3000.other.net"), 3000);
  assert.equal(tm.matchHost("4000.other.net"), null);

  await assert.rejects(D.update("other.net", { tunnels: "none" }), /dashboard, some tunnels, or both/);
  await D.update("other.net", { label: "aegis", tunnels: "none" });
  assert.deepEqual(recs.filter((r) => r.type === "CNAME").map((r) => r.name), ["aegis.other.net"], "the wildcard goes once no tunnel answers there");
  assert.equal(tm.matchHost("3000.other.net"), null);
  assert.ok(D.isDashboard("aegis.other.net"));

  await D.remove("other.net");
  assert.deepEqual(recs.map((r) => r.id), ["mx"]);
  assert.deepEqual(D.list(), []);
  assert.equal(D.isDashboard("aegis.other.net"), false);
  assert.equal(existsSync(join(D.dir, "other.net")), false);
});

test("never takes over someone else's record; a failed add gives the authorization back", async () => {
  const { D, recs, calls, authorize } = setup([{ id: "x", name: "*.other.net", type: "A", content: "198.51.100.9" }]);
  await authorize();
  await assert.rejects(D.add({ label: "aegis", tunnels: "all" }), /\*\.other\.net already has a A record \(198\.51\.100\.9\)/);
  assert.deepEqual(D.list(), []);
  assert.deepEqual(D.view().pending, { zone: "other.net", via: "login" }, "authorize once, try again");
  assert.ok(existsSync(D.pendingPath()));
  assert.ok(!calls.some((c) => c.startsWith("POST")) || recs.every((r) => r.id === "x" || r.name === "aegis.other.net"));
  await assert.rejects(D.add({ label: "9000" }), /only digits/);
  const v = await D.add({ label: "aegis", tunnels: "none" });
  assert.equal(v.domains[0].dashboard, "aegis.other.net");
  assert.equal(recs.find((r) => r.id === "x").content, "198.51.100.9", "theirs is untouched");
});

test("a domain the credentials Aegis already holds can reach needs no sign-in; else a login or a token", async () => {
  const { D, state, ran } = setup([], { reaches: { "tok-z1": ["other.net"], "good-token-0123456789abcdefghijklmnop": ["third.org"] } });
  await assert.rejects(D.check("example.com"), /already the main domain/);
  await assert.rejects(D.check("not a domain"), /Type the domain/);
  let v = await D.check("https://Other.NET/");
  assert.deepEqual(v.pending, { zone: "other.net", via: "the main domain's" }, "the main domain's token reaches it");
  assert.equal(v.need, null);
  D.forget();
  v = await D.check("third.org");
  assert.equal(v.pending, null);
  assert.deepEqual(v.need, { zone: "third.org" }, "nothing reaches it: ask");
  await assert.rejects(D.useToken("third.org", "short"), /doesn't look like/);
  await assert.rejects(D.useToken("third.org", "wrong-token-0123456789abcdefghijklmnop"), /can't edit third\.org/);
  v = await D.useToken("third.org", "good-token-0123456789abcdefghijklmnop");
  assert.deepEqual(v.pending, { zone: "third.org", via: "your API token" });
  assert.equal(state.cfTokens.length, 1, "kept for the next domain");
  assert.equal(D.tokens().at(-1).why, "your API token");
  // VPS route, no dashboard: no Cloudflare tunnel at all, so a DNS-only token is enough
  await assert.rejects(D.add({ label: "", tunnels: "all", route: "vps" }), /Link your VPS first/);
  assert.equal(ran.filter((x) => x === "create").length, 0);
});

test("through your VPS: a wildcard certificate goes on the agent before the record points at it; back to Cloudflare undoes it", async () => {
  const order = [], pushed = [], removed = [];
  const relay = { configured: () => true, host: () => "203.0.113.7", ip: async () => "203.0.113.7", outdated: () => null, version: () => "1.1.0",
                  ready: async () => ({ ok: true }), push: async (cur, suffix) => { order.push("push"); pushed.push([suffix, cur.names]); }, remove: async (s) => { removed.push(s); } };
  const { D, tm, recs, ran, acme, authorize } = setup([{ id: "mx", name: "other.net", type: "MX", content: "mail.other.net" }], { relay });
  const realApi = D.api.bind(D);
  D.api = (d, m, p, b) => { if (m === "POST" && b?.type !== "TXT") order.push(`record ${b.name}`); return realApi(d, m, p, b); };
  await authorize();
  const v = await D.add({ label: "", tunnels: "all" });
  assert.equal(v.domains[0].route, "vps", "your VPS by default once it's linked");
  assert.deepEqual(acme.issued, ["*.other.net"]);
  assert.deepEqual(pushed, [[".other.net", ["*.other.net"]]]);
  assert.deepEqual(order, ["push", "record *.other.net"], "the certificate is on the VPS first");
  assert.deepEqual(recs.filter((r) => r.name === "*.other.net").map((r) => [r.type, r.content, r.proxied]), [["A", "203.0.113.7", false]]);
  assert.equal(ran.filter((x) => x === "create").length, 0, "no dashboard there: no Cloudflare tunnel");
  assert.ok(D.wantsRelay());
  assert.ok(v.domains[0].cert.notAfter > Date.now());
  assert.equal(recs.some((r) => r.type === "TXT"), false, "the check record is gone again");
  await tm.create({ port: 3000 });
  assert.equal(tm.matchHost("3000.other.net"), 3000);

  // renewals and a link that comes back: the same certificate isn't asked for again
  await D.pushAll();
  assert.deepEqual(acme.issued, ["*.other.net"]);
  assert.equal(pushed.length, 2);

  // to Cloudflare: a tunnel now, a proxied CNAME instead of the A record, the VPS lets go of the zone
  await D.update("other.net", { route: "cloudflare", label: "home" });
  assert.equal(ran.filter((x) => x === "create").length, 1);
  assert.deepEqual(recs.filter((r) => r.name.endsWith("other.net") && r.type !== "MX").map((r) => [r.name, r.type, r.proxied]).sort(),
    [["*.other.net", "CNAME", true], ["home.other.net", "CNAME", true]]);
  assert.deepEqual(removed, [".other.net"]);
  assert.equal(D.wantsRelay(), false);

  // the VPS can't be reached: nothing moves
  relay.ready = async () => ({ ok: false, error: "its SSH port doesn't answer" });
  await assert.rejects(D.update("other.net", { route: "vps" }), /isn't reachable: its SSH port doesn't answer\. Nothing was moved/);
  assert.equal(recs.find((r) => r.name === "*.other.net").type, "CNAME");
  await D.remove("other.net");
  assert.deepEqual(recs.map((r) => r.id), ["mx"]);
});

test("subdomains: a wildcard one through your VPS (its own certificate), a single one for one tunnel; removing one lets go of it", async () => {
  const pushed = [], removed = [];
  const relay = { configured: () => true, host: () => "203.0.113.7", ip: async () => "203.0.113.7", outdated: () => null, version: () => "1.2.0",
                  ready: async () => ({ ok: true }), push: async (cur, suffix) => { pushed.push([suffix, cur.names]); }, remove: async (s) => { removed.push(s); } };
  const { D, tm, recs, acme, authorize } = setup([], { relay });
  await authorize();
  await D.add({ label: "", tunnels: "all", route: "vps" });
  await tm.create({ port: 3000 });
  await tm.create({ port: 3001 });
  const v = await D.update("other.net", { subs: [{ name: "apps", wildcard: true }, { name: "Blog", wildcard: false, port: 3001 }] });
  assert.deepEqual(v.domains[0].subs.map((x) => x.host), ["*.apps.other.net", "blog.other.net"]);
  assert.deepEqual(acme.issued, ["*.other.net", "*.apps.other.net"], "a certificate of its own for the wildcard subdomain");
  assert.deepEqual(pushed.at(-1), [".apps.other.net", ["*.apps.other.net"]], "on the agent with its own suffix");
  assert.deepEqual(v.domains[0].cert.names, ["*.other.net", "*.apps.other.net"]);
  assert.deepEqual(recs.map((r) => [r.name, r.type, r.content]).sort(),
    [["*.apps.other.net", "A", "203.0.113.7"], ["*.other.net", "A", "203.0.113.7"], ["blog.other.net", "A", "203.0.113.7"]]);
  // names: every tunnel under the wildcard subdomain; the single one is 3001's only
  assert.equal(tm.matchHost("3000.apps.other.net"), 3000);
  assert.equal(tm.matchHost("3001.apps.other.net"), 3001);
  assert.equal(tm.matchHost("blog.other.net"), 3001);
  assert.equal(tm.matchHost("3000.other.net"), 3000, "the domain's own wildcard still works");
  for (const n of ["x.3000.apps.other.net", "3000.nope.other.net", "apps.other.net"]) assert.equal(tm.matchHost(n), null, n);
  const also = (port) => tm.alsoFor(tm.get(port)).filter((a) => !a.hidden).map((a) => a.host);
  assert.deepEqual(also(3000), ["3000.other.net", "3000.apps.other.net"]);
  assert.deepEqual(also(3001), ["blog.other.net", "3001.other.net", "3001.apps.other.net"]);
  // what doesn't go together
  await assert.rejects(D.update("other.net", { label: "apps" }), /dashboard's name there/);
  await assert.rejects(D.update("other.net", { tunnels: "none" }), /set its tunnels to all or picked first/);
  await assert.rejects(D.update("other.net", { route: "cloudflare" }), /Cloudflare's free certificate covers one/);
  await assert.rejects(D.update("other.net", { subs: [{ name: "123", wildcard: true }] }), /only digits/);
  await assert.rejects(D.update("other.net", { subs: [{ name: "a.b", wildcard: true }] }), /one level/);
  await assert.rejects(D.update("other.net", { subs: [{ name: "x", wildcard: false }] }), /Pick the tunnel/);
  await assert.rejects(D.update("other.net", { subs: [{ name: "x", wildcard: true }, { name: "x", port: 3000 }] }), /twice/);
  assert.equal(D.get("other.net").subs.length, 2, "nothing changed");
  // the wildcard subdomain goes: its record, and the VPS lets go of its suffix
  await D.update("other.net", { subs: [{ name: "blog", wildcard: false, port: 3001 }] });
  assert.deepEqual(removed, [".apps.other.net"]);
  assert.deepEqual(recs.map((r) => r.name).sort(), ["*.other.net", "blog.other.net"]);
  assert.equal(tm.matchHost("3000.apps.other.net"), null);
  // only single subdomains, no wildcard: still a certificate for the names one level down
  await D.update("other.net", { tunnels: "none" });
  assert.deepEqual(recs.map((r) => r.name), ["blog.other.net"]);
  assert.equal(tm.matchHost("blog.other.net"), 3001);
  assert.equal(tm.matchHost("3000.other.net"), null);
  assert.ok(D.wantsRelay());
  await D.remove("other.net");
  assert.deepEqual(recs, []);
  assert.ok(removed.includes(".other.net"));
});

test("subdomains through Cloudflare: a single one is a proxied record and a rule before the wildcard; a wildcard one is refused", async () => {
  const { D, tm, recs, authorize } = setup();
  await authorize();
  await D.add({ label: "home", tunnels: "all", route: "cloudflare", subs: [{ name: "blog", port: 3000 }] });
  await assert.rejects(D.update("other.net", { subs: [{ name: "apps", wildcard: true }] }), /through your VPS/);
  assert.deepEqual(recs.map((r) => [r.name, r.type, r.proxied]).sort(), [["*.other.net", "CNAME", true], ["blog.other.net", "CNAME", true], ["home.other.net", "CNAME", true]]);
  const yml = readFileSync(D.writeConfig(D.get("other.net")), "utf8");
  assert.ok(yml.indexOf('"blog.other.net"') > 0 && yml.indexOf('"blog.other.net"') < yml.indexOf('"*.other.net"'), "the single name before the wildcard");
  await tm.create({ port: 3000 });
  assert.equal(tm.matchHost("blog.other.net"), 3000);
});
