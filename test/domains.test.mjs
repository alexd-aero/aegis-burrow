// More domains (burrow/domains.mjs): another zone's dashboard name and tunnel names, beside the main domain.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Domains } from "../burrow/domains.mjs";
import { TunnelManager } from "../burrow/tunnels.mjs";

const pem = (zoneID) => `-----BEGIN ARGO TUNNEL TOKEN-----\n${Buffer.from(JSON.stringify({ zoneID, accountID: "acc", apiToken: "tok-" + zoneID })).toString("base64")}\n-----END ARGO TUNNEL TOKEN-----\n`;

const managers = [];
after(() => { for (const tm of managers) tm.stop(); });
function setup(records = []) {
  const dir = mkdtempSync(join(tmpdir(), "aegis-dom-"));
  const state = { domain: { mainHost: "aegis.example.com", tunnelId: "t-main", cert: "/nonexistent" } };
  const settings = { get: (k) => state[k], set: (p) => Object.assign(state, p) };
  const recs = [...records], calls = [];
  // Cloudflare, faked: one zone's records
  const cfApi = async (token, method, path, body) => {
    calls.push(`${method} ${path.replace(/^\/zones\/[^/]+/, "")}`);
    if (/^\/zones\/[^/]+$/.test(path)) return { name: { z2: "other.net", z1: "example.com" }[path.split("/")[2]] };
    const id = /dns_records\/([^/?]+)/.exec(path)?.[1];
    if (method === "GET") { const n = /name=([^&]+)/.exec(path); return n ? recs.filter((r) => r.name === decodeURIComponent(n[1])) : recs; }
    if (method === "POST") { const r = { id: "r" + calls.length, ...body }; recs.push(r); return r; }
    if (method === "PUT") { const i = recs.findIndex((r) => r.id === id); recs[i] = { id, ...body }; return recs[i]; }
    if (method === "DELETE") { recs.splice(recs.findIndex((r) => r.id === id), 1); return {}; }
  };
  const run = async (bin, args) => ({ code: 0, out: args.includes("create") ? "Created tunnel x with id 11111111-2222-3333-4444-555555555555" : "", err: "" });
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "aegis-dom-tun-")), domain: state.domain, quick: null, forbiddenPorts: [4310], log: () => {} });
  const D = new Domains({ settings, dataDir: dir, origin: () => ({ url: "https://127.0.0.1:4301", insecure: true }), log: () => {},
    bin: () => "/bin/true", mainZone: () => "example.com", onChange: (l) => tm.useExtras(l), cfApi, run, autostart: false });
  tm.useExtras(D.list(), (z) => D.takenOn(z));
  tm.cfApi = async (method, path, body) => (method === "GET" ? [] : { id: "m1", ...body });
  tm.dnsAnswers = async () => true;
  managers.push(tm);
  // what `cloudflared tunnel login` would leave behind
  const authorize = async (zone = "z2") => { const f = join(dir, "got.pem"); writeFileSync(f, pem(zone)); await D.takeCert(f); };
  return { D, tm, recs, calls, state, authorize };
}

test("another domain: its own authorization, the dashboard there, a wildcard for tunnels", async () => {
  const { D, tm, recs, authorize } = setup([{ id: "mx", name: "other.net", type: "MX", content: "mail.other.net" }, { id: "w", name: "www.other.net", type: "A", content: "203.0.113.4" }]);
  await assert.rejects(D.add({ label: "aegis" }), /Authorize Cloudflare/);
  await assert.rejects(authorize("z1"), /already the main domain/);
  await authorize();
  assert.deepEqual(D.view().pending, { zone: "other.net" });
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
  assert.deepEqual(D.view().pending, { zone: "other.net" }, "authorize once, try again");
  assert.ok(existsSync(D.pendingPath()));
  assert.ok(!calls.some((c) => c.startsWith("POST")) || recs.every((r) => r.id === "x" || r.name === "aegis.other.net"));
  await assert.rejects(D.add({ label: "9000" }), /only digits/);
  const v = await D.add({ label: "aegis", tunnels: "none" });
  assert.equal(v.domains[0].dashboard, "aegis.other.net");
  assert.equal(recs.find((r) => r.id === "x").content, "198.51.100.9", "theirs is untouched");
});
