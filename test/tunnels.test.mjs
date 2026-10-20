// Tunnels with a name of their own (t.sub): naming, routing, and never taking
// over a DNS record that isn't Burrow's.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TunnelManager } from "../burrow/tunnels.mjs";

const DOMAIN = { mainHost: "aegis.example.com", tunnelId: "t-1", cert: "/nonexistent" };
function manager(records = {}) {
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "burrow-tun-")), domain: DOMAIN, quick: null, forbiddenPorts: [4310], log: () => {} });
  const dns = [];
  // Cloudflare, faked: GET finds `records`, POST/DELETE are noted
  tm.cfApi = async (method, path, body) => {
    dns.push(`${method} ${path}`);
    if (method === "GET") { const name = decodeURIComponent(/name=([^&]+)/.exec(path)[1]); return records[name] || []; }
    return { id: "r" + dns.length, ...body };
  };
  tm.detectScheme = async () => "http";
  tm.refreshFavicon = () => {}; tm.healthOne = () => {};
  tm.dnsAnswers = async () => true;
  return { tm, dns };
}

test("default and custom names", async () => {
  const { tm } = manager();
  try {
    await tm.create({ port: 3000 });
    assert.equal(tm.hostFor(3000), "tunnel-3000-aegis.example.com");
    assert.equal(tm.matchHost("tunnel-3000-aegis.example.com"), 3000);
    const t = await tm.update(3000, { sub: "Grafana" });
    assert.equal(t.sub, "grafana");
    assert.equal(t.url, "https://grafana.example.com");
    assert.equal(tm.matchHost("grafana.example.com"), 3000);
    assert.equal(tm.matchHost("tunnel-3000-aegis.example.com"), null, "the old name stops answering");
    await tm.update(3000, { sub: "" });
    assert.equal(tm.hostFor(3000), "tunnel-3000-aegis.example.com");
    assert.equal(tm.matchHost("grafana.example.com"), null);
    // a full name is fine too
    assert.equal((await tm.update(3000, { sub: "app.example.com" })).sub, "app");
  } finally { tm.stop(); }
});

test("names that are refused", async () => {
  const { tm } = manager({ "mail.example.com": [{ type: "MX", name: "mail.example.com", content: "x" }],
                           "www.example.com": [{ type: "CNAME", name: "www.example.com", content: "elsewhere.net" }],
                           "mine.example.com": [{ type: "CNAME", name: "mine.example.com", content: "t-1.cfargotunnel.com" }] });
  try {
    await tm.create({ port: 3000, sub: "one" });
    await tm.create({ port: 4000 });
    for (const bad of ["-x", "a_b", "aegis", "tunnel-5-x", "one", "mail", "www", "x".repeat(41)]) {
      await assert.rejects(tm.update(4000, { sub: bad }), Error, bad);
    }
    assert.equal((await tm.update(4000, { sub: "mine" })).sub, "mine", "a record that already points at our tunnel is ours");
    await assert.rejects(tm.create({ port: 5000, sub: "mine" }), /already uses/);
  } finally { tm.stop(); }
});

// Secure reverse tunneling: where a Pages site really is, and its paths.
import { parseSite, makeLock, checkLock } from "../burrow/tunnels.mjs";

test("Pages addresses people paste", () => {
  const url = (s) => parseSite(s).url;
  assert.equal(url("github.com/You/project"), "https://you.github.io/project/");
  assert.equal(url("https://github.com/you/project.git"), "https://you.github.io/project/");
  assert.equal(url("https://github.com/you/project/tree/main/docs"), "https://you.github.io/project/");
  assert.equal(url("github.com/you/you.github.io"), "https://you.github.io/");
  assert.equal(url("you.github.io"), "https://you.github.io/");
  assert.equal(url("https://you.github.io/project/docs/"), "https://you.github.io/project/docs/");
  assert.equal(url("gitlab.com/group/sub/project/-/tree/main"), "https://group.gitlab.io/sub/project/");
  assert.equal(url("https://group.gitlab.io/project"), "https://group.gitlab.io/project/");
  assert.equal(parseSite("gitlab.com/g/p").provider, "gitlab");
  for (const bad of ["", "example.com", "github.com", "evil.com/you.github.io", "you.github.io.evil.com", "https://x.github.io/a'b/", "ftp.github.io.x"]) {
    assert.throws(() => parseSite(bad), Error, bad);
  }
});

test("a site's paths, both ways", async () => {
  const { tm } = manager();
  try {
    const t = { kind: "site", site: parseSite("you.github.io/project") };
    assert.equal(tm.sitePath(t, "/"), "/project/");
    assert.equal(tm.sitePath(t, "/css/a.css?v=1"), "/project/css/a.css?v=1");
    assert.equal(tm.sitePath(t, "/project/css/a.css"), "/project/css/a.css", "the site's own absolute links");
    assert.equal(tm.sitePath(t, "/project"), "/project");
    assert.equal(tm.siteLocation(t, "https://you.github.io/project/docs/"), "/docs/");
    assert.equal(tm.siteLocation(t, "https://you.github.io/project"), "/");
    assert.equal(tm.siteLocation(t, "/project/x?y=1#z"), "/x?y=1#z");
    assert.equal(tm.siteLocation(t, "https://elsewhere.com/x"), "https://elsewhere.com/x");
    const h = tm.siteHeaders(t, { headers: { host: "docs.example.com", "cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "1.2.3.4",
                                             referer: "https://docs.example.com/a", accept: "*/*" } });
    assert.deepEqual(h, { host: "you.github.io", referer: "https://you.github.io/project/a", accept: "*/*" });
  } finally { tm.stop(); }
});

test("a tunnel's own password", async () => {
  const lock = makeLock("correct horse");
  assert.ok(checkLock(lock, "correct horse"));
  assert.ok(!checkLock(lock, "correct hors"));
  assert.ok(!checkLock(lock, undefined));
  assert.ok(!JSON.stringify(lock).includes("correct"));
  // any length works, even a few characters; only an empty one is refused
  for (const pw of ["1", "abcd", "abcdefgh"]) assert.ok(checkLock(makeLock(pw), pw));
  assert.throws(() => makeLock(""), /Set a password/);

  const { tm } = manager();
  try {
    let t = await tm.create({ port: 3000 });
    assert.equal(t.access, "login", "the Aegis login by default");
    await assert.rejects(tm.create({ port: 3001, access: "password" }), /Set a password/);
    await assert.rejects(tm.update(3000, { access: "password" }), /Set a password/);
    assert.equal(tm.get(3000).access, "login", "nothing changed");
    t = await tm.update(3000, { access: "password", password: "a long one!" });
    assert.equal(t.access, "password"); assert.equal(t.locked, true);
    const epoch = tm.get(3000).lock.epoch;
    t = await tm.update(3000, { access: "login" });
    assert.equal(tm.get(3000).lock.epoch, epoch, "the password is kept for later");
    await tm.update(3000, { access: "password" });
    await tm.update(3000, { password: "another one" });
    assert.notEqual(tm.get(3000).lock.epoch, epoch, "a new password signs everyone out");
    assert.ok(checkLock(tm.get(3000).lock, "another one"));
    assert.equal(tm.summary(tm.get(3000)).lock, undefined, "the hash never leaves");
  } finally { tm.stop(); }
});

test("sites: an address of their own, never public", async () => {
  const { tm } = manager();
  tm.checkSite = async () => {};
  try {
    await assert.rejects(tm.create({ site: "you.github.io/p" }), /address of its own/);
    await assert.rejects(tm.create({ site: "you.github.io/p", sub: "docs", access: "public" }), /behind a password/);
    const s = await tm.create({ site: "github.com/you/p", sub: "docs", access: "password", password: "site pass 1" });
    assert.equal(s.port, 70001); assert.equal(s.kind, "site");
    assert.equal(s.url, "https://docs.example.com"); assert.equal(s.target, "https://you.github.io/p/");
    assert.equal(tm.matchHost("docs.example.com"), 70001);
    assert.equal((await tm.create({ site: "you.gitlab.io", sub: "two" })).port, 70002);
    await assert.rejects(tm.update(70001, { access: "public" }), /behind a password/);
    await assert.rejects(tm.update(70001, { sub: "" }), /address of its own/);
    assert.equal((await tm.update(70001, { site: "you.github.io/q" })).target, "https://you.github.io/q/");
    assert.equal(tm.get(70001).targetHost, "you.github.io");
  } finally { tm.stop(); }
});

test("a renamed tunnel's record goes with it; leftovers are swept; DNS on its way", async () => {
  const { tm, dns } = manager();
  try {
    let answers = false;
    tm.dnsAnswers = async () => answers;
    await tm.create({ port: 3000, sub: "grafana" });
    assert.equal(tm.list()[0].dns.ready, false, "a brand-new name is on its way");
    answers = true;
    await new Promise((ok) => setTimeout(ok, 1700));
    assert.equal(tm.list()[0].dns.ready, true, "until public DNS answers");
    dns.length = 0;
    await tm.remove(3000);
    assert.ok(dns.includes(`GET /dns_records?name=${encodeURIComponent("grafana.example.com")}`), "removing looks up its own name, not the default");
    // records Burrow made for tunnels that are gone; others are left alone
    const C = "t-1.cfargotunnel.com", K = "aegis (burrow tunnels)";
    await tm.create({ port: 4000 });
    tm.cfApi = async (method, path) => {
      dns.push(`${method} ${path}`);
      return method === "GET" ? [
        { id: "a", name: "db-test.example.com", content: C, comment: K },
        { id: "b", name: "tunnel-4000-aegis.example.com", content: C, comment: K },
        { id: "c", name: "aegis.example.com", content: C, comment: K },
        { id: "d", name: "other.example.com", content: C, comment: "someone else's" },
        { id: "e", name: "elsewhere.example.com", content: "x.cfargotunnel.com", comment: K },
      ] : {};
    };
    dns.length = 0;
    await tm.sweepDns();
    assert.deepEqual(dns.filter((d) => d.startsWith("DELETE")), ["DELETE /dns_records/a"]);
  } finally { tm.stop(); }
});

// One wildcard record for every tunnel: NAME.<prefix>.<zone>.
function wildManager(records = {}) {
  const m = manager(records);
  // the fake keeps a zone: GET by name, or every CNAME for the sweep
  const zone = new Map();
  m.tm.cfApi = async (method, path, body) => {
    m.dns.push(`${method} ${path}`);
    const ty = /type=([A-Z]+)/.exec(path);
    if (method === "GET" && ty) return [...zone.values()].filter((r) => r.type === ty[1]);
    if (method === "GET") { const name = decodeURIComponent(/name=([^&]+)/.exec(path)[1]); return records[name] || (zone.has(name) ? [zone.get(name)] : []); }
    if (method === "POST") { const r = { id: "r" + m.dns.length, ...body }; zone.set(body.name, r); return r; }
    if (method === "DELETE") { for (const [k, v] of zone) if (path.endsWith("/" + v.id)) zone.delete(k); return {}; }
    return { id: "r" + m.dns.length, ...body };
  };
  m.zone = zone;
  return m;
}

test("wildcard naming: one record, NAME.prefix.zone, and back", async () => {
  const { tm, dns, zone } = wildManager();
  try {
    await tm.create({ port: 3000 });
    await tm.create({ port: 4000, sub: "radio" });
    assert.deepEqual([...zone.keys()].sort(), ["radio.example.com", "tunnel-3000-aegis.example.com"]);

    tm.certCovers = async () => false;
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "tunnel" }), /certificate/);
    assert.equal(tm.hostFor(4000), "radio.example.com", "nothing moved after a refused switch");

    tm.certCovers = async () => true;
    const info = await tm.setNaming({ mode: "wildcard", prefix: "tunnel" });
    assert.equal(info.record, "*.tunnel.example.com");
    assert.deepEqual([...zone.keys()], ["*.tunnel.example.com"], "the per-tunnel records are gone");
    assert.equal(tm.hostFor(4000), "radio.tunnel.example.com");
    assert.equal(tm.hostFor(3000), "3000.tunnel.example.com");
    assert.equal(tm.matchHost("radio.tunnel.example.com"), 4000);
    assert.equal(tm.matchHost("3000.tunnel.example.com"), 3000);
    assert.equal(tm.matchHost("4000.tunnel.example.com"), null, "a named tunnel answers only to its name");
    assert.equal(tm.matchHost("x.radio.tunnel.example.com"), null);
    assert.equal(tm.matchHost("radio.example.com"), null);

    const posts = dns.filter((d) => d.startsWith("POST")).length;
    await tm.create({ port: 5000, sub: "grafana" });
    assert.equal(dns.filter((d) => d.startsWith("POST")).length, posts, "a new tunnel adds no record");
    assert.equal(tm.matchHost("grafana.tunnel.example.com"), 5000);
    await assert.rejects(tm.update(5000, { sub: "123" }), /digits/);
    await tm.remove(5000);
    assert.ok(zone.has("*.tunnel.example.com"), "removing a tunnel keeps the wildcard");

    await tm.setNaming({ mode: "wildcard", prefix: "t.home" });
    assert.deepEqual([...zone.keys()], ["*.t.home.example.com"], "a new prefix replaces the old wildcard");
    assert.equal(tm.hostFor(4000), "radio.t.home.example.com");

    await tm.setNaming({ mode: "record" });
    assert.deepEqual([...zone.keys()].sort(), ["radio.example.com", "tunnel-3000-aegis.example.com"]);
    assert.equal(tm.matchHost("radio.example.com"), 4000);
  } finally { tm.stop(); }
});

test("wildcard naming: an empty prefix is *.zone, and real records win", async () => {
  const { tm } = wildManager({ "www.example.com": [{ type: "CNAME", name: "www.example.com", content: "elsewhere.net" }] });
  try {
    tm.certCovers = async () => true;
    await tm.create({ port: 3000 });
    const info = await tm.setNaming({ mode: "wildcard", prefix: "" });
    assert.equal(info.record, "*.example.com");
    assert.equal(tm.hostFor(3000), "3000.example.com");
    await assert.rejects(tm.update(3000, { sub: "www" }), /wins over the wildcard/);
    await assert.rejects(tm.update(3000, { sub: "aegis" }), /dashboard/);
    assert.equal(tm.matchHost("aegis.example.com"), null, "the dashboard's own name is never a tunnel");
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "bad_prefix" }), /prefix/);
  } finally { tm.stop(); }
});

test("wildcard naming through a relay: an A record, no certificate check, relay-ask", async () => {
  const { tm, zone } = wildManager();
  try {
    let asked = 0;
    tm.certCovers = async () => { asked++; return false; };
    await tm.create({ port: 3000, sub: "radio" });
    await tm.create({ port: 4000 });
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "tunnel", relay: "not-an-ip" }), /IP address/);
    const info = await tm.setNaming({ mode: "wildcard", prefix: "tunnel", relay: "203.0.113.7" });
    assert.equal(asked, 0, "a relay brings its own certificates");
    assert.equal(info.relay, "203.0.113.7");
    const w = zone.get("*.tunnel.example.com");
    assert.deepEqual([w.type, w.content, w.proxied], ["A", "203.0.113.7", false]);
    assert.deepEqual([...zone.keys()], ["*.tunnel.example.com"]);
    assert.equal(tm.relayAsk("radio.tunnel.example.com"), true);
    assert.equal(tm.relayAsk("4000.tunnel.example.com"), true);
    assert.equal(tm.relayAsk("nope.tunnel.example.com"), false, "only real tunnels get certificates");
    await tm.update(4000, { enabled: false });
    assert.equal(tm.relayAsk("4000.tunnel.example.com"), false, "nor paused ones");
    // back through Cloudflare: the A record goes, a proxied CNAME comes
    tm.certCovers = async () => true;
    await tm.setNaming({ mode: "wildcard", prefix: "tunnel" });
    const c = zone.get("*.tunnel.example.com");
    assert.deepEqual([c.type, c.proxied], ["CNAME", true]);
    assert.equal(tm.relayAsk("radio.tunnel.example.com"), false, "no relay, no questions");
  } finally { tm.stop(); }
});

test("leaving the Worker front: names checked first, every Custom Domain removed (stale ones too), nothing half-done on failure", async () => {
  const { tm, zone } = wildManager();
  try {
    await tm.create({ port: 3000, sub: "chat-demo" });
    await tm.create({ port: 4000 });
    tm.naming = { mode: "wildcard", prefix: "tunnel", certs: "worker", relay: null };
    // Cloudflare's Workers, faked: a Custom Domain comes with a read-only AAAA 100:: record
    const domains = new Map();
    const front = { linked: true, removed: [], failNext: false,
      deploy: async () => ({ script: "aegis-tunnels-aegis" }),
      domains: async () => [...domains.values()],
      addDomain: async (hostname) => { domains.set(hostname, { id: "d-" + hostname, hostname, service: "aegis-tunnels-aegis" });
                                       zone.set(hostname, { id: "z-" + hostname, type: "AAAA", name: hostname, content: "100::", proxied: true, meta: { read_only: true } }); },
      removeDomain: async () => 0, certReady: async () => true,
      removeAll: async () => {
        assert.equal(front.accountId, "acc-1", "it knows which account (not accounts/null)");
        assert.equal(front.zoneId, "zone-1");
        if (front.failNext) { front.failNext = false; throw new Error("Authentication error"); }
        const gone = [...domains.keys()]; domains.clear(); front.removed.push(...gone);
        setTimeout(() => { for (const h of gone) zone.delete(h); }, 50);          // Cloudflare drops the records a moment later
        return gone;
      } };
    tm.front = front;
    tm.cf = () => ({ account: "acc-1", zone: "zone-1" });
    for (const h of ["chat-demo.tunnel.example.com", "4000.tunnel.example.com", "22.tunnel.example.com"]) await front.addDomain(h);   // 22: an old tunnel's
    // a failure removing them: rejected, still on the Worker, its names put back
    front.failNext = true;
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "tunnel", relay: "203.0.113.7" }), /Couldn't remove the Worker's names.*nothing was moved/);
    assert.equal(tm.naming.certs, "worker");
    assert.ok(domains.has("chat-demo.tunnel.example.com"), "the names are still the Worker's");
    // now it works: the Worker's own AAAA records don't block chat-demo, all three go, the wildcard comes
    const info = await tm.setNaming({ mode: "wildcard", prefix: "tunnel", relay: "203.0.113.7" });
    assert.equal(info.relay, "203.0.113.7");
    assert.deepEqual(front.removed.sort(), ["22.tunnel.example.com", "4000.tunnel.example.com", "chat-demo.tunnel.example.com"]);
    assert.deepEqual([...zone.keys()], ["*.tunnel.example.com"], "only the wildcard is left");
    assert.equal(zone.get("*.tunnel.example.com").content, "203.0.113.7");
    assert.equal(tm.matchHost("chat-demo.tunnel.example.com"), 3000);
  } finally { tm.stop(); }
});

test("a foreign record still blocks a name, Worker or not", async () => {
  const { tm } = wildManager({ "mail.tunnel.example.com": [{ type: "A", name: "mail.tunnel.example.com", content: "198.51.100.1" }] });
  try {
    await tm.create({ port: 3000, sub: "mail" });
    tm.naming = { mode: "wildcard", prefix: "tunnel", certs: "worker", relay: null };
    tm.front = { linked: true, deploy: async () => ({}), domains: async () => [], removeAll: async () => [], removeDomain: async () => 0, addDomain: async () => {}, certReady: async () => true };
    await assert.rejects(tm.setNaming({ mode: "wildcard", prefix: "tunnel", relay: "203.0.113.7" }), /mail \(tunnel-3000\).*already has a A record/);
    assert.equal(tm.naming.certs, "worker", "nothing moved");
  } finally { tm.stop(); }
});
