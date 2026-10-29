// A tunnel's fallback: the relay agent stands in while home doesn't answer
// (relay/agent.mjs 1.5 "standby", burrow/standby.mjs). Everything runs here, on
// local ports: an agent in-process, a fake "home", and the gate's syncer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { sign, startAgent, previewToken, standbyPath, VERSION, FEATURES } from "../relay/agent.mjs";
import { RelayLink } from "../burrow/relaylink.mjs";
import { Standby, scanFolder, cleanFallback } from "../burrow/standby.mjs";
import { makeLock, SCRYPT } from "../burrow/tunnels.mjs";

const HOST = "millspark.tunnel.example.com";
const tmp = () => mkdtempSync(join(tmpdir(), "standby-test-"));
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const free = async () => { const s = createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; };
const sha = (b) => createHash("sha256").update(b).digest("hex");
function call(port, path, { method = "GET", headers = {}, body } = {}) {
  return new Promise((res, rej0) => {
    const rej = (e) => { e.message += ` (${method} ${path})`; rej0(e); };
    const r = request({ host: "127.0.0.1", port, path, method, headers }, (x) => { const c = []; x.on("data", (d) => c.push(d)); x.on("end", () => res({ status: x.statusCode, headers: x.headers, body: Buffer.concat(c).toString() })); });
    r.on("error", rej); r.end(body);
  });
}

// home: answers "ok", "502", or never ("hang"); closed: refused
async function setup(extra = {}) {
  const key = randomBytes(32), dir = tmp();
  const home = { mode: "ok", srv: null, port: await free() };
  home.start = () => new Promise((r) => {
    home.srv = createServer((req, res) => {
      if (home.mode === "hang") return;
      if (home.mode === "502") { res.writeHead(502); return res.end("bad gateway"); }
      res.writeHead(200, { "content-type": "text/plain" }); res.end("hello from home");
    });
    home.srv.listen(home.port, "127.0.0.1", r);
  });
  home.stop = () => new Promise((r) => { home.srv.closeAllConnections?.(); home.srv.close(() => r()); });
  await home.start();
  const ctl = await free();
  const agent = startAgent({ key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: home.port, controlPort: ctl, httpPort: await free(),
                             mode: "caddy", certDir: join(dir, "certs"), reload: false, standbyWait: 400, ...extra }, { log: () => {} });
  await new Promise((r) => setTimeout(r, 100));
  const front = agent.front.address().port;
  const visit = (path, o = {}) => call(front, path, { ...o, headers: { host: HOST, "x-aegis-client": o.ip || "203.0.113.9", ...(o.headers || {}) } });
  const ctlCall = (method, url, body) => call(ctl, url, { method, body, headers: { "x-aegis-relay": sign(key, { host: "agent", ip: "-", method, url }) } });
  const put = (host, path, buf, s = sha(buf)) => ctlCall("PUT", `/standby/${host}/file?path=${encodeURIComponent(path)}&sha=${s}`, buf);
  const commit = (host, cfg, s) => { const b = Buffer.from(JSON.stringify(cfg)); return ctlCall("POST", `/standby/${host}/commit?sha=${s || sha(b)}`, b); };
  const A = { key, dir, home, agent, ctl, visit, ctlCall, put, commit };
  A.close = async () => { A.agent.close(); await home.stop().catch(() => {}); };       // the agent running now (a test may restart it)
  return A;
}
const SITE = { "index.html": "<!doctype html><title>Mills Park</title>display", "app.js": "console.log('hi')", "docs/index.html": "the docs" };
async function sendSite(A, files = SITE, cfg = {}) {
  const manifest = {};
  for (const [p, body] of Object.entries(files)) { const b = Buffer.from(body); manifest[p] = { sha: sha(b), size: b.length }; assert.equal((await A.put(HOST, p, b)).status, 200, p); }
  return A.commit(HOST, { kind: "folder", hosts: [HOST], access: "public", files: manifest, fp: "x", ...cfg });
}

test("agent 1.5: standby is a feature; home answers while it can", async () => {
  assert.ok(VERSION.split(".").map(Number).reduce((a, x) => a * 1000 + x, 0) >= 1005000, VERSION);
  assert.ok(FEATURES.includes("standby"));
  const A = await setup();
  try {
    assert.equal((await A.visit("/")).body, "hello from home");
    assert.equal((await sendSite(A)).status, 200);
    const r = await A.visit("/");
    assert.equal(r.body, "hello from home", "a stand-in changes nothing while home answers");
    assert.equal(r.headers["x-aegis-standby"], undefined);
    assert.equal((await call(A.agent.front.address().port, "/", { headers: { host: "evil.example.org", "x-aegis-client": "1.2.3.4" } })).status, 421, "foreign names still 421");
  } finally { await A.close(); }
});

test("standby: home refused, 502, or silent -> the folder; files, index.html, the SPA, HEAD, other methods", async () => {
  const A = await setup();
  try {
    await sendSite(A);
    await A.home.stop();                                                    // refused
    let r = await A.visit("/");
    assert.equal(r.status, 200);
    assert.match(r.body, /Mills Park/);
    assert.equal(r.headers["x-aegis-standby"], "1");
    assert.equal(r.headers["cache-control"], "no-store");
    assert.match(r.headers["content-type"], /text\/html/);
    r = await A.visit("/app.js");
    assert.equal(r.body, "console.log('hi')");
    assert.match(r.headers["content-type"], /javascript/);
    r = await A.visit("/docs");
    assert.equal(r.status, 302); assert.equal(r.headers.location, "/docs/");
    assert.equal((await A.visit("/docs/")).body, "the docs");
    assert.match((await A.visit("/some/client/route?x=1")).body, /Mills Park/, "a single-page app's own routes get index.html");
    r = await A.visit("/app.js", { method: "HEAD" });
    assert.equal(r.status, 200); assert.equal(r.body, ""); assert.equal(r.headers["content-length"], String(SITE["app.js"].length));
    r = await A.visit("/form", { method: "POST", body: "x=1" });
    assert.equal(r.status, 503, "only reading works on a stand-in");
    for (const p of ["/../site.json", "/%2e%2e/site.json", "/..%2fsite.json", "/files/../site.json", "/.staging", "/%2e%2e%2f%2e%2e%2fconfig.json"]) {
      const x = await A.visit(p);
      assert.ok(!/scrypt|"hosts"/.test(x.body), `${p} must not leak site.json`);
    }
    await A.home.start(); A.home.mode = "502";
    r = await A.visit("/");
    assert.equal(r.headers["x-aegis-standby"], "1", "home says 502: the stand-in");
    A.home.mode = "hang";
    const t0 = Date.now();
    r = await A.visit("/");
    assert.equal(r.headers["x-aegis-standby"], "1", "home says nothing: the stand-in after the short wait");
    assert.ok(Date.now() - t0 < 3000);
    A.home.mode = "ok";
    assert.equal((await A.visit("/")).body, "hello from home", "home is back: home again");
    assert.ok(A.agent.stats.standby >= 5);
  } finally { await A.close(); }
});

test("standby control: signed only; a body must be the signed sha; clean paths; limits; a commit needs every file", async () => {
  const A = await setup();
  try {
    assert.equal((await call(A.ctl, "/standby")).status, 401, "unsigned");
    const b = Buffer.from("hello");
    assert.equal((await A.put(HOST, "index.html", Buffer.from("evil"), sha(b))).status, 400, "the body isn't the signed one");
    for (const p of ["../x", "a/../../x", ".env", "a/.git/config", "/abs", "a//b", "a\\b", ""]) assert.equal((await A.put(HOST, p, b)).status, 400, `path ${JSON.stringify(p)}`);
    assert.equal(standbyPath("css/site.css"), "css/site.css");
    assert.equal((await A.put("evil.example.org", "a", b)).status, 400, "a name this relay doesn't carry");
    assert.equal((await A.put(HOST, "index.html", b)).status, 200);
    const one = { "index.html": { sha: sha(b), size: b.length } };
    assert.equal((await A.commit(HOST, { kind: "folder", hosts: [HOST], access: "public", files: one }, "0".repeat(64))).status, 400, "commit body bound by its sha");
    let r = await A.commit(HOST, { kind: "folder", hosts: [HOST], access: "public", files: { ...one, "missing.js": { sha: sha("nope"), size: 4 } } });
    assert.equal(r.status, 409); assert.deepEqual(JSON.parse(r.body).missing, ["missing.js"]);
    const many = {}; for (let i = 0; i < 2001; i++) many[`f${i}.txt`] = { sha: sha(b), size: 5 };
    assert.match(JSON.parse((await A.commit(HOST, { kind: "folder", hosts: [HOST], access: "public", files: many })).body).error, /more than 2000 files/);
    assert.match(JSON.parse((await A.commit(HOST, { kind: "folder", hosts: [HOST], access: "public", files: { "big.bin": { sha: sha(b), size: 51 * 1048576 } } })).body).error, /more than 50 MB/);
    assert.match(JSON.parse((await A.commit(HOST, { kind: "folder", hosts: [HOST], access: "password", files: one })).body).error, /hash/, "a locked one needs the hash");
    assert.match(JSON.parse((await A.commit(HOST, { kind: "folder", hosts: [HOST, "x.other.org"], access: "public", files: one })).body).error, /hosts/);
    r = await A.commit(HOST, { kind: "folder", hosts: [HOST], access: "public", files: one, fp: "abc" });
    assert.equal(r.status, 200);
    const list = JSON.parse((await A.ctlCall("GET", "/standby")).body);
    assert.deepEqual(list.sites.map((s) => [s.host, s.files, s.fp]), [[HOST, 1, "abc"]]);
    assert.equal(JSON.parse((await A.ctlCall("GET", `/standby/${HOST}`)).body).files["index.html"].sha, sha(b));
    // kept across a restart of the agent
    A.agent.close();
    const B = startAgent({ key: A.key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: 1, controlPort: await free(), httpPort: await free(),
                           mode: "caddy", certDir: join(A.dir, "certs"), reload: false }, { log: () => {} });
    assert.equal(B.sites.get(HOST).files.size, 1, "the stand-in is still there after a restart");
    B.close();
    A.agent = startAgent({ key: A.key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort: 1, controlPort: A.ctl, httpPort: await free(), mode: "caddy", certDir: join(A.dir, "certs"), reload: false }, { log: () => {} });
    await new Promise((res) => setTimeout(res, 100));
    assert.equal(JSON.parse((await A.ctlCall("DELETE", `/standby/${HOST}`)).body).removed, true);
    assert.deepEqual(JSON.parse((await A.ctlCall("GET", "/standby")).body).sites, []);
  } finally { await A.close(); }
});

test("standby behind a password: the tunnel's hash, a form, a host cookie, a new password locks it again, tries are limited", async () => {
  const A = await setup();
  try {
    let lock = makeLock("correct horse");
    assert.equal((await sendSite(A, SITE, { access: "password", lock, scrypt: SCRYPT })).status, 200);
    await A.home.stop();
    let r = await A.visit("/app.js");
    assert.equal(r.status, 401); assert.match(r.body, /This site has a password/);
    assert.ok(!r.body.includes("console.log"));
    const form = (pw, ip) => A.visit("/__aegis_standby/unlock", { method: "POST", ip, headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password: pw, next: "/app.js" }).toString() });
    r = await form("wrong");
    assert.equal(r.status, 401); assert.match(r.body, /not it/);
    r = await form("correct horse");
    assert.equal(r.status, 303); assert.equal(r.headers.location, "/app.js");
    const ck = r.headers["set-cookie"][0];
    assert.match(ck, /^__Host-aegis-sb=\d+\.[\w-]{43}; Path=\/; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax$/);
    const cookie = ck.split(";")[0];
    r = await A.visit("/app.js", { headers: { cookie } });
    assert.equal(r.status, 200); assert.equal(r.body, "console.log('hi')");
    assert.equal((await A.visit("/app.js", { headers: { cookie: cookie.replace(/.$/, (c) => (c === "A" ? "B" : "A")) } })).status, 401, "a forged cookie");
    const evil = (await A.visit("/__aegis_standby/unlock", { method: "POST", body: "password=correct+horse&next=//evil.example" })).headers.location;
    assert.equal(evil, "/", "next stays on this site");
    // a new password on the tunnel: a new epoch, every cookie out
    lock = makeLock("battery staple");
    await sendSite(A, SITE, { access: "password", lock, scrypt: SCRYPT });
    assert.equal((await A.visit("/app.js", { headers: { cookie } })).status, 401);
    // ten wrong tries from one address, then a pause even for the right one
    for (let i = 0; i < 10; i++) await form("nope", "198.51.100.7");
    r = await form("battery staple", "198.51.100.7");
    assert.equal(r.status, 429);
    assert.equal((await form("battery staple", "198.51.100.8")).status, 303, "others aren't held up");
  } finally { await A.close(); }
});

test("a message page, and the preview link that shows the stand-in while home is up", async () => {
  const A = await setup();
  try {
    assert.equal((await A.commit(HOST, { kind: "page", hosts: [HOST], access: "public", title: "Back <soon>", message: "The display is updating." })).status, 200);
    let r = await A.visit("/");
    assert.equal(r.body, "hello from home");
    const tok = previewToken(A.key, HOST);
    r = await A.visit(`/?__aegis_standby=${encodeURIComponent(tok)}`);
    assert.equal(r.status, 303); assert.equal(r.headers.location, "/");
    const cookie = r.headers["set-cookie"][0].split(";")[0];
    assert.match(r.headers["set-cookie"][0], /Max-Age=600/);
    r = await A.visit("/", { headers: { cookie } });
    assert.equal(r.status, 503);
    assert.equal(r.headers["x-aegis-standby"], "1");
    assert.match(r.body, /Back &lt;soon&gt;/, "escaped");
    assert.match(r.body, /The display is updating\./);
    assert.match(r.body, /http-equiv="refresh" content="30"/);
    assert.match(r.body, /prefers-color-scheme:dark/);
    assert.equal((await A.visit(`/?__aegis_standby=${encodeURIComponent(previewToken(randomBytes(32), HOST))}`)).status, 403, "a token of another key");
    assert.equal((await A.visit(`/?__aegis_standby=${encodeURIComponent(previewToken(A.key, HOST, 600e3, Date.now() - 700e3))}`)).status, 403, "an expired one");
  } finally { await A.close(); }
});

test("scanFolder: limits, hidden files out, links out of the folder out; cleanFallback's rules", () => {
  const d = tmp(), site = join(d, "site"), outside = join(d, "outside");
  mkdirSync(join(site, "css"), { recursive: true }); mkdirSync(join(site, ".git"), { recursive: true }); mkdirSync(outside);
  writeFileSync(join(site, "index.html"), "hi"); writeFileSync(join(site, "css", "a.css"), "body{}"); writeFileSync(join(site, ".env"), "SECRET=1");
  writeFileSync(join(site, ".git", "config"), "x"); writeFileSync(join(outside, "secret.txt"), "nope");
  symlinkSync(join(outside, "secret.txt"), join(site, "leak.txt"));
  symlinkSync(join(site, "index.html"), join(site, "home.html"));
  const s = scanFolder(site);
  assert.deepEqual(Object.keys(s.files).sort(), ["css/a.css", "home.html", "index.html"]);
  assert.equal(s.skipped.hidden, 2); assert.equal(s.skipped.outside, 1);
  assert.equal(s.files["index.html"].sha, sha("hi"));
  assert.throws(() => scanFolder(site, { files: 2, bytes: 1e9 }), /more than 2 files/);
  assert.throws(() => scanFolder(site, { files: 100, bytes: 3 }), /more than/);
  assert.throws(() => scanFolder(join(d, "nope")), /doesn't exist/);
  // the rules for what the user asks
  assert.equal(cleanFallback({ kind: "folder", dir: site }, { access: "public" }).dir, site);
  assert.throws(() => cleanFallback({ kind: "folder", dir: "relative/path" }, {}), /full path/);
  assert.throws(() => cleanFallback({ kind: "folder", dir: "/" }, {}), /not the whole disk/);
  assert.throws(() => cleanFallback({ kind: "folder", dir: site }, { access: "login" }), /password of its own/);
  const fb = cleanFallback({ kind: "folder", dir: site, password: "pw" }, { access: "login" });
  assert.ok(fb.lock.hash && fb.lock.epoch, "stored as a hash");
  assert.ok(!JSON.stringify(fb).includes('"pw"'));
  assert.equal(cleanFallback({ kind: "page", title: "Back soon" }, {}).message.length > 0, true, "a page gets words by default");
  assert.throws(() => cleanFallback({ kind: "nope" }, {}), /off", "folder" or "page/);
  assert.throws(() => cleanFallback({ kind: "page", title: "x".repeat(81) }, {}), /80/);
  rmSync(d, { recursive: true });
});

test("the gate's syncer: only what changed goes over; off removes it; a restarted or emptied agent gets it again; preview works", async () => {
  const A = await setup();
  const d = tmp(), site = join(d, "public");
  mkdirSync(join(site, "img"), { recursive: true });
  writeFileSync(join(site, "index.html"), "<title>Mills Park</title>v1");
  writeFileSync(join(site, "app.js"), "1");
  writeFileSync(join(site, "img", "logo.svg"), "<svg/>");
  // the real RelayLink, pointed at the agent's control port
  const L = new RelayLink({ dataDir: d, log: () => {} });
  Object.assign(L.state, { key: A.key.toString("base64url"), vps: { host: "vps.example.com", port: 22 }, installed: { at: Date.now() } });
  L.localCtl = A.ctl; L.link = { state: "up" };
  L.agent = await L.control("GET", "/status");
  const calls = [];
  const control = L.control.bind(L);
  L.control = (m, p, b, t) => { calls.push(`${m} ${p.split("?")[0]}`); return control(m, p, b, t); };
  const t = { port: 8793, access: "password", lock: makeLock("mills"), sub: "millspark" };
  const T = { tunnels: new Map([[8793, t]]), get: (p) => T.tunnels.get(Number(p)), save() { this.saved = (this.saved || 0) + 1; } };
  const S = new Standby({ tunnels: T, link: L, log: () => {}, hostsOf: () => [HOST], quietMs: 50 });
  try {
    let v = await S.configure(8793, { kind: "folder", dir: site });
    assert.equal(v.status.error, null, v.status.error);
    assert.equal(v.status.files, 3); assert.equal(v.status.sent, 3); assert.equal(v.status.agent, true);
    assert.equal(v.hasPassword, false, "a password tunnel uses its own lock");
    await A.home.stop();
    assert.equal((await A.visit("/")).status, 401, "behind the tunnel's password on the VPS too");
    // one file changes: one file goes
    writeFileSync(join(site, "app.js"), "2");
    calls.length = 0;
    v = await S.sync(8793);
    assert.equal(v.status.sent, 1);
    assert.deepEqual(calls.filter((c) => c.startsWith("PUT")), [`PUT /standby/${HOST}/file`]);
    // nothing changed: a look, nothing sent
    calls.length = 0;
    await S.tick();
    assert.deepEqual(calls, ["GET /standby"]);
    // the agent lost it (reinstalled): sent again on the next look
    await L.control("DELETE", `/standby/${HOST}`);
    await S.tick();
    assert.equal(A.agent.sites.get(HOST).files.size, 3);
    // the watcher sees a change by itself
    writeFileSync(join(site, "index.html"), "<title>Mills Park</title>v2");
    for (let i = 0; i < 100 && !A.agent.sites.get(HOST).files.get("index.html")?.sha.startsWith(sha("<title>Mills Park</title>v2").slice(0, 12)); i++) await new Promise((r) => setTimeout(r, 50));
    assert.equal(A.agent.sites.get(HOST).files.get("index.html").sha, sha("<title>Mills Park</title>v2"), "fs.watch, then a quiet moment, then a sync");
    // a new tunnel password: the VPS copy follows (the hash, never the password)
    t.lock = makeLock("new one");
    await S.tick();
    assert.equal(A.agent.sites.get(HOST).lock.epoch, t.lock.epoch);
    // the preview link
    const pv = S.preview(8793);
    assert.match(pv.url, new RegExp(`^https://${HOST.replace(/\./g, "\\.")}/\\?__aegis_standby=p1\\.`));
    const r = await A.visit(new URL(pv.url).pathname + new URL(pv.url).search);
    assert.equal(r.status, 303);
    // the link down: said so, nothing breaks
    L.link = { state: "down" };
    await S.tick();
    assert.match(t.fallback.status.error, /link to your VPS is down/);
    L.link = { state: "up" };
    // off: gone from the VPS
    v = await S.configure(8793, { kind: "off" });
    assert.equal(v.kind, "off");
    assert.equal(A.agent.sites.has(HOST), false);
    // a login tunnel needs the fallback's own password
    t.access = "login";
    await assert.rejects(S.configure(8793, { kind: "page", title: "Back soon" }), /password of its own/);
    v = await S.configure(8793, { kind: "page", title: "Back soon", password: "standby pw" });
    assert.equal(v.hasPassword, true);
    assert.equal(A.agent.sites.get(HOST).kind, "page");
    // an agent too old for it: explained
    L.agent = { ...L.agent, version: "1.4.0", features: ["zones", "update", "edge", "fleet"] };
    await S.tick();
    assert.match(t.fallback.status.error, /1\.4\.0: fallbacks need 1\.5\.0/);
    // not offered where the VPS doesn't carry the tunnel
    const S2 = new Standby({ tunnels: T, link: L, log: () => {}, eligible: () => "Your tunnels don't go through a VPS of yours." });
    assert.equal(S2.view(8793).offered, false);
    await assert.rejects(S2.configure(8793, { kind: "page" }), /VPS of yours/);
    const rt = await S.route("GET", "/tunnels/8793/fallback", async () => ({}));
    assert.equal(rt.status, 200); assert.equal(rt.json.kind, "page");
    assert.ok(!JSON.stringify(rt.json).includes(t.fallback.lock.hash), "the route never shows the hash");
  } finally { S.stop(); await A.close(); rmSync(d, { recursive: true }); }
});
