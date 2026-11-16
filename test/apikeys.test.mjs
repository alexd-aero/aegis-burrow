// Developer API keys (aegis/apikeys.mjs): making, checking, scopes, apps, expiry,
// address lists, the rate limit, rolling and revoking, and what no key can reach.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApiKeys, scopeFor, tokenOf, stripKey } from "../aegis/apikeys.mjs";

const store = () => new ApiKeys({ file: join(mkdtempSync(join(tmpdir(), "aegis-keys-")), "apikeys.json") });
const req = (key, how = "bearer") => ({ headers: how === "bearer" ? { authorization: `Bearer ${key}` } : { "x-aegis-key": key } });

test("a key is shown once, kept as a hash, and opens the API by either header", () => {
  const K = store();
  assert.equal(K.enabled, false);
  const made = K.create({ name: "deploy bot", scopes: ["full"] }, "alex");
  assert.match(made.key, /^aegis_[0-9a-f]{10}_[A-Za-z0-9_-]{43}$/);
  assert.equal(K.enabled, true, "making a key switches the API on");
  K.flush();
  const disk = readFileSync(K.file, "utf8");
  assert.ok(!disk.includes(made.key.split("_")[2]), "the secret is never written down");
  assert.equal(statSync(K.file).mode & 0o777, 0o600);
  assert.ok(!JSON.stringify(K.view()).includes(K.keys[0].hash), "the dashboard never sees the hash");
  for (const how of ["bearer", "header"]) assert.equal(K.check(req(made.key, how), "1.2.3.4").key.id, made.id);
  assert.equal(K.check({ headers: {} }, "1.2.3.4"), null, "no key: not a key request");
  assert.equal(K.check(req("aegis_nope"), "1.2.3.4").status, 401);
  assert.equal(K.check(req(made.key.slice(0, -1) + (made.key.endsWith("A") ? "B" : "A")), "1.2.3.4").status, 401, "a wrong secret");
  // reloads from disk
  const again = new ApiKeys({ file: K.file });
  assert.equal(again.check(req(made.key), "1.2.3.4").key.name, "deploy bot");
});

test("scopes: what each call needs, and what no key reaches", () => {
  assert.equal(scopeFor("GET", "/tunnels"), "read");
  assert.equal(scopeFor("POST", "/tunnels"), "tunnels");
  assert.equal(scopeFor("PATCH", "/tunnels/8080"), "tunnels");
  assert.equal(scopeFor("POST", "/addons/bulwark/update"), "addons");
  assert.equal(scopeFor("POST", "/x/burrow-pages/sites"), "addons");
  assert.equal(scopeFor("POST", "/fleet/abc/probe"), "machines");
  assert.equal(scopeFor("POST", "/domains"), "network");
  assert.equal(scopeFor("POST", "/shield/ban"), "network");
  assert.equal(scopeFor("POST", "/update/apply"), "system");
  assert.equal(scopeFor("POST", "/prefs"), "system");
  for (const [m, p] of [["GET", "/keys"], ["POST", "/keys"], ["GET", "/devkeys"], ["POST", "/password"], ["POST", "/setup"], ["POST", "/askpass"],
                        ["POST", "/addons/x/runspec"], ["POST", "/addons/jobs/0123456789ab/line"]]) assert.equal(scopeFor(m, p), "never", `${m} ${p}`);

  const K = store();
  const ro = K.create({ name: "ro", scopes: ["read"] }).id, tun = K.create({ name: "tun", scopes: ["tunnels"] }).id;
  const full = K.create({ name: "full", scopes: ["full", "read"] }).id, apps = K.create({ name: "apps", scopes: ["apps"] }).id;
  const k = (id) => K.keys.find((x) => x.id === id);
  assert.deepEqual(k(full).scopes, ["full"], "full swallows the rest");
  assert.ok(K.may(k(ro), "GET", "/tunnels"));
  assert.ok(!K.may(k(ro), "POST", "/tunnels"));
  assert.ok(K.may(k(tun), "GET", "/tunnels"), "a writing scope can read too");
  assert.ok(K.may(k(tun), "DELETE", "/tunnels/80"));
  assert.ok(!K.may(k(tun), "POST", "/addons/a/update"));
  assert.ok(!K.may(k(apps), "GET", "/tunnels"), "apps alone is only the apps");
  assert.ok(K.may(k(full), "POST", "/update/apply"));
  assert.ok(!K.may(k(full), "POST", "/keys"), "not even full makes keys");
  assert.ok(!K.may(k(full), "POST", "/password"));
});

test("apps: every app, or only the picked ones, and only with apps or full", () => {
  const K = store();
  const get = (spec) => { const id = K.create(spec).id; return K.keys.find((x) => x.id === id); };
  const all = get({ name: "a", scopes: ["apps"] });
  const some = get({ name: "b", scopes: ["apps"], apps: ["tunnel:8080", "app:termix", "bogus", "app:Bad!"] });
  const none = get({ name: "c", scopes: ["tunnels"] });
  assert.deepEqual(some.apps, ["tunnel:8080", "app:termix"]);
  assert.ok(K.opens(all, "tunnel:1"));
  assert.ok(K.opens(some, "tunnel:8080") && K.opens(some, "app:termix"));
  assert.ok(!K.opens(some, "tunnel:9090"));
  assert.ok(!K.opens(none, "tunnel:8080"), "no apps scope: no apps");
});

test("off, switched off, expired, wrong address, rate limit", () => {
  const K = store();
  const m = K.create({ name: "x", scopes: ["read"], rate: 3, ips: "10.0.0.0/8, 2001:db8::/32" });
  assert.equal(K.check(req(m.key), "10.1.2.3").key.id, m.id);
  assert.equal(K.check(req(m.key), "::ffff:10.9.9.9").key.id, m.id, "IPv4-mapped");
  assert.equal(K.check(req(m.key), "2001:db8::5").key.id, m.id);
  assert.equal(K.check(req(m.key), "192.168.1.5").status, 403);
  const r = K.check(req(m.key), "10.0.0.1");
  assert.equal(r.status, 429, "the 4th call in a minute");
  assert.ok(r.retry > 0);
  K.windows.clear();
  K.update(m.id, { disabled: true });
  assert.equal(K.check(req(m.key), "10.0.0.1").status, 403);
  K.update(m.id, { disabled: false });
  K.setEnabled(false);
  assert.match(K.check(req(m.key), "10.0.0.1").error, /switched off/);
  K.setEnabled(true);
  K.keys[0].expires = Date.now() - 1;
  assert.match(K.check(req(m.key), "10.0.0.1").error, /expired/);
  assert.throws(() => K.create({ name: "y", scopes: ["read"], ips: "not-an-ip" }), /isn't an address/);
  assert.throws(() => K.create({ name: "y", scopes: ["read"], expires: Date.now() - 5 }), /future/);
  assert.throws(() => K.create({ name: "", scopes: ["read"] }), /name/);
  assert.throws(() => K.create({ name: "y", scopes: [] }), /scope/);
  const d = K.create({ name: "z", scopes: ["read"], expires: "30d" });
  assert.ok(Math.abs(d.expires - (Date.now() + 30 * 864e5)) < 5000);
});

test("rolling makes the old key worthless; revoking ends it; the log keeps both", () => {
  const K = store();
  const a = K.create({ name: "a", scopes: ["full"] }, "alex");
  const b = K.roll(a.id, "alex");
  assert.notEqual(a.key, b.key);
  assert.equal(K.check(req(a.key), "1.1.1.1").status, 401);
  assert.equal(K.check(req(b.key), "1.1.1.1").key.id, a.id);
  K.used(K.keys[0], { ip: "1.1.1.1", method: "POST", path: "/tunnels", status: 200 });
  K.used(K.keys[0], { ip: "1.1.1.1", method: "GET", path: "/tunnels", status: 200 });
  assert.equal(K.keys[0].uses, 2);
  assert.equal(K.keys[0].last.path, "/tunnels");
  K.remove(a.id, "alex");
  assert.equal(K.check(req(b.key), "1.1.1.1").status, 401);
  const events = K.view().log.map((e) => e.event);
  assert.deepEqual(events, ["revoked", "POST /tunnels", "rolled (the old key stopped working)", "created"], "GETs aren't logged one by one");
});

test("the key never reaches an app", () => {
  const r1 = { headers: { authorization: "Bearer aegis_0123456789_abc", "x-aegis-key": "aegis_x" } };
  assert.equal(tokenOf(r1), "aegis_x");
  stripKey(r1);
  assert.deepEqual(r1.headers, {});
  const r2 = { headers: { authorization: "Basic dXNlcjpwYXNz" } };
  stripKey(r2);
  assert.equal(r2.headers.authorization, "Basic dXNlcjpwYXNz", "an app's own Authorization stays");
});
