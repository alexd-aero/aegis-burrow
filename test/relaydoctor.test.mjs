// The relay doctor: tunnels through a VPS that look live but turn every visitor
// away ("Not signed by your relay", ECONNREFUSED), found from the outside and fixed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request } from "node:http";
import { createServer as createHttps } from "node:https";
import { spawn, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { RelayLink } from "../burrow/relaylink.mjs";
import { RelayDoctor, probePath, portAnswers } from "../burrow/relaydoctor.mjs";
import { ensureSshd } from "../relay/agent.mjs";
import { WATCH, REVIVE, standbySetup } from "../aegis/fleet-ops.mjs";
import { writeFileSync } from "node:fs";
import { createHmac } from "node:crypto";

const AGENT = fileURLToPath(new URL("../relay/agent.mjs", import.meta.url));
const tmp = () => mkdtempSync(join(tmpdir(), "relay-doctor-test-"));
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const free = async () => { const s = createServer(); const p = await listen(s); await new Promise((r) => s.close(r)); return p; };

// a VPS: the real agent in its own process, its clock `skew` ms off
async function vps({ key, upstreamPort, skew = 0 }) {
  const dir = tmp(), controlPort = await free(), httpPort = await free();
  const cfg = { key: key.toString("base64url"), suffix: ".tunnel.example.com", upstreamPort, controlPort, httpPort, mode: "caddy",
                certDir: join(dir, "certs"), caddySite: join(dir, "caddy", "aegis-relay.caddy"), reload: false, clockCommands: false };
  const code = `const real = Date.now; Date.now = () => real() + Number(process.env.SKEW);
    const { startAgent } = await import(process.env.AGENT);
    startAgent(JSON.parse(process.env.CFG), { log: () => {} }); console.log("ready");`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", code], { env: { ...process.env, SKEW: String(skew), AGENT, CFG: JSON.stringify(cfg) }, stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((r) => child.stdout.once("data", r));
  await new Promise((r) => setTimeout(r, 150));
  return { controlPort, httpPort, close: () => child.kill() };
}
// Caddy in front of it: TLS with a certificate for *.tunnel.example.com, the visitor's address in x-aegis-client
function caddy(httpPort) {
  const dir = tmp();
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj", "/CN=*.tunnel.example.com",
                           "-addext", "subjectAltName=DNS:*.tunnel.example.com", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
  const cert = readFileSync(join(dir, "c.pem"));
  const srv = createHttps({ key: readFileSync(join(dir, "k.pem")), cert }, (req, res) => {
    const up = request({ host: "127.0.0.1", port: httpPort, method: req.method, path: req.url, headers: { ...req.headers, "x-aegis-client": "198.51.100.20" } }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    up.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(up);
  });
  return { srv, ca: cert };
}
// this gate's relay listener, as aegis/gate.mjs has it: signed or refused, and the ping
function home(link, gateKey = randomBytes(32)) {
  return createServer((req, res) => {
    const host = String(req.headers.host).replace(/:\d+$/, "");
    const ip = link.verifyRequest(req, host);
    if (!ip) { res.writeHead(403, { "Content-Type": "text/plain", "X-Aegis-Relay": "bad-signature" }); return res.end("Not signed by your relay."); }
    if (req.url.startsWith("/__aegis-relay/ping?")) {
      res.writeHead(200, { "Content-Type": "application/json", "X-Aegis-Relay": "ok" });
      const n = /n=([^&]+)/.exec(req.url)[1];
      return res.end(JSON.stringify({ n, at: Date.now(), gate: gateOf(gateKey)(n), standby: !!link.standby }));
    }
    res.end("the app");
  });
}
const gateOf = (k) => (n) => createHmac("sha256", k).update(String(n)).digest("base64url").slice(0, 22);
function linkTo(key, controlPort) {
  const link = new RelayLink({ dataDir: tmp(), log: () => {} });
  link.state = { ...link.state, key: key.toString("base64url"), vps: { host: "203.0.113.7", port: 22 }, installed: { at: 1 } };
  link.localCtl = controlPort; link.link = { state: "up", since: Date.now() };
  return link;
}

test("a VPS whose clock is 90 s ahead: every visitor refused, until this machine signs in the VPS's time", async () => {
  const key = randomBytes(32);
  let link;
  const gate = home({ verifyRequest: (...a) => link.verifyRequest(...a) });
  const v = await vps({ key, upstreamPort: await listen(gate), skew: 90e3 });
  link = linkTo(key, v.controlPort);
  const { srv, ca } = caddy(v.httpPort);
  const port = await listen(srv);
  const probe = () => probePath({ ip: "127.0.0.1", port, host: `x${randomBytes(2).toString("hex")}.tunnel.example.com`, nonce: randomBytes(9).toString("base64url"), ca });
  try {
    // the report: "Not signed by your relay", while everything here says live
    assert.equal((await probe()).kind, "bad-signature");
    // the agent says its time when it refuses: the second try is signed in it
    const st = await link.control("GET", "/status");
    assert.ok(st.now > 0 && st.features.includes("clock"), st.version);
    assert.ok(Math.abs(link.skew - 90e3) < 3000, `learned the skew (${link.skew})`);
    assert.equal(link.view().clock.used, link.skew, "and says so (Settings → Domain)");
    assert.equal((await probe()).kind, "ok", "visitors get through again");
    // the clock fix: signed, a sane time only
    await assert.rejects(link.control("POST", "/clock", { truth: 5 }), /isn't a time/);
    const r = await link.control("POST", "/clock", { truth: Date.now() });
    assert.ok(Math.abs(r.before - 90e3) < 3000);
    assert.deepEqual(r.how, ["not allowed here"]);
  } finally { v.close(); srv.close(); gate.close(); }
});

test("the doctor: finds it from the outside, keeps it working, says which clock and which app", async () => {
  const key = randomBytes(32);
  let link;
  const gate = home({ verifyRequest: (...a) => link.verifyRequest(...a) });
  const v = await vps({ key, upstreamPort: await listen(gate), skew: -75e3 });
  link = linkTo(key, v.controlPort);
  const { srv, ca } = caddy(v.httpPort);
  const port = await listen(srv), dead = await free();
  const notices = [];
  const doc = new RelayDoctor({
    link, dataDir: tmp(), log: () => {}, wanted: () => true, bringUp: async () => {}, zones: () => [".tunnel.example.com"], pushCerts: async () => {},
    tunnels: () => [{ port: dead, name: "radio", targetPort: dead }],
    clock: async () => ({ offset: 0, sources: 3 }),
    probe: (o) => probePath({ ...o, ip: "127.0.0.1", port }),
    dns: async () => ({ "1.1.1.1": ["203.0.113.7"], "8.8.8.8": ["104.21.3.4"] }),
    ca, notify: (n) => notices.push(n),
  });
  try {
    const r = await doc.run({ reason: "asked" });
    const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
    assert.equal(by["path:.tunnel.example.com"].ok, true, "carried, in the VPS's time");
    assert.equal(r.ok, true);
    assert.equal(by.clock.ok, false, "the VPS's clock is still wrong (this agent may not set it)");
    assert.match(by.clock.detail, /VPS's clock is 75 s behind/);
    assert.match(by.clock.hint, /timedatectl set-ntp true/);
    assert.equal(by.apps.ok, false);
    assert.match(by.apps.detail, /radio .*connection refused/);
    assert.equal(by["dns:.tunnel.example.com"].ok, true, "one resolver is enough");
    assert.equal(notices.length, 0, "reachable: no alarm");
  } finally { v.close(); srv.close(); gate.close(); }
});

test("probe: what a visitor would get, named", async () => {
  const key = randomBytes(32);
  const v = await vps({ key, upstreamPort: await free() });             // nothing at home: the link isn't there
  const { srv, ca } = caddy(v.httpPort);
  const port = await listen(srv);
  const p = (o) => probePath({ ip: "127.0.0.1", port, nonce: "abcdefghij", ca, host: "a.tunnel.example.com", ...o });
  try {
    assert.equal((await p()).kind, "home-offline");
    assert.equal((await p({ host: "a.other.example.org" })).kind, "cert", "a name the certificate doesn't cover");
    assert.equal((await p({ ca: undefined })).kind, "cert", "a certificate browsers don't trust");
    assert.equal((await p({ port: await free() })).kind, "front-down");
    assert.equal(await portAnswers(await free()), "connection refused");
    assert.equal(await portAnswers(port), null);
  } finally { v.close(); srv.close(); }
});

test("the doctor: fixes what it can, rings the bell when it can't, and clears it once fixed", async () => {
  let kind = "home-offline", stops = 0, ups = 0, cleared = 0;
  const link = { state: { vps: { host: "203.0.113.7" } }, link: { state: "up", since: Date.now() }, configured: () => true, clock: null, skew: 0,
                 control: async () => ({ version: "1.6.0" }), outdated: () => null, can: () => true, stop: () => { stops++; }, checked: null };
  const notices = [], resolved = [];
  const doc = new RelayDoctor({
    link, log: () => {}, wanted: () => true, bringUp: async () => { ups++; }, zones: () => [".t.example.com"], pushCerts: async () => {},
    root: () => ({ run: async (s) => { if (/pkill -u aegis-relay/.test(s)) { cleared++; kind = "ok"; } return { code: 0, out: "ok" }; } }),
    clock: async () => null, dns: async () => null,
    probe: async ({ nonce }) => ({ kind, detail: kind === "ok" ? "fine" : "the VPS can't reach this machine", nonce }),
    notify: (n) => notices.push(n), resolved: (k) => resolved.push(k),
  });
  let r = await doc.run({ reason: "scheduled" });
  assert.equal(r.ok, true, "the stale forward on the VPS was cleared, the link restarted");
  assert.equal(cleared, 1); assert.equal(stops, 1); assert.equal(ups, 1);
  assert.match(r.checks.find((c) => c.id.startsWith("path:")).fixed, /cleared an old session/);

  // nothing helps: the bell on the second scheduled failure, at once when asked
  kind = "unreachable";
  r = await doc.run({ reason: "scheduled" });
  assert.equal(r.ok, false); assert.equal(notices.length, 0);
  r = await doc.run({ reason: "scheduled" });
  assert.equal(notices.length, 1);
  assert.equal(notices[0].level, "critical"); assert.equal(notices[0].key, "relay-doctor");
  assert.match(notices[0].body, /firewall/);
  kind = "ok";
  r = await doc.run({ reason: "scheduled" });
  assert.equal(r.ok, true);
  assert.deepEqual(resolved, ["relay-doctor"]);
  assert.equal(notices.at(-1).title, "Your tunnels are reachable again");

  // the tunnels don't use the VPS: nothing to check, nothing to fix
  const idle = new RelayDoctor({ link, log: () => {}, wanted: () => false, zones: () => [] });
  assert.equal((await idle.run()).idle, true);
});

test("a standby copy with the same keys holds the VPS link: the doctor tells it from this gate", async () => {
  const key = randomBytes(32), mine = randomBytes(32), theirs = randomBytes(32);
  let link;
  const clone = home({ verifyRequest: (...a) => link.verifyRequest(...a), standby: true }, theirs);
  const v = await vps({ key, upstreamPort: await listen(clone) });
  link = linkTo(key, v.controlPort);
  const { srv, ca } = caddy(v.httpPort);
  const port = await listen(srv);
  const p = (gateId) => probePath({ ip: "127.0.0.1", port, host: "a.tunnel.example.com", nonce: randomBytes(9).toString("base64url"), ca, gateId });
  try {
    assert.equal((await p(gateOf(theirs))).kind, "ok", "the copy itself would think all is well");
    const r = await p(gateOf(mine));
    assert.equal(r.kind, "other-aegis");
    assert.equal(r.standby, true);
    assert.match(r.detail, /standby copy/);
    assert.equal((await p(undefined)).kind, "ok", "no id to compare (an older caller): as before");
  } finally { v.close(); srv.close(); clone.close(); }
});

test("the doctor asks the standby to step aside, clears the VPS sessions and links again", async () => {
  let holder = "clone", asked = 0, ups = 0;
  const link = { state: { vps: { host: "203.0.113.7" } }, link: { state: "up", since: Date.now() }, configured: () => true, clock: null, skew: 0,
                 control: async () => ({ version: "1.6.1" }), outdated: () => null, can: () => true, stop: () => {}, checked: null };
  const doc = new RelayDoctor({
    link, log: () => {}, wanted: () => true, bringUp: async () => { ups++; }, zones: () => [".t.example.com"], pushCerts: async () => {},
    root: () => ({ run: async () => { if (asked) holder = "me"; return { code: 0, out: "ok" }; } }),
    standbyBack: () => { asked++; return "homer"; }, clock: async () => null, dns: async () => null,
    probe: async () => holder === "me" ? { kind: "ok", detail: "fine" } : { kind: "other-aegis", standby: true, detail: "your standby copy holds the VPS link" },
  });
  doc.standbyWait = 0;
  const r = await doc.run({ reason: "scheduled" });
  assert.equal(asked, 1); assert.equal(ups, 1);
  assert.equal(r.ok, true);
  assert.match(r.checks.find((c) => c.id.startsWith("path:")).fixed, /standby on homer to step aside.*cleared its session/);
});

test("sshd: the relay user's forward goes to loopback only, and a dead link lets go; nothing else is touched", () => {
  const dir = tmp(), file = join(dir, "sshd_config");
  const base = "Port 22\nGatewayPorts yes\n";
  writeFileSync(file, base);
  let eff = "gatewayports yes\nclientaliveinterval 0\n", checks = 0, reloads = [], bad = false;
  const run = (cmd, args) => {
    if (cmd === "sshd" && args[0] === "-T") return eff;
    if (cmd === "sshd" && args[0] === "-t") { checks++; if (bad) throw Object.assign(new Error("x"), { stderr: "line 9: Bad configuration option" }); return ""; }
    if (cmd === "systemctl") { reloads.push(args[1]); return ""; }
    throw new Error("unexpected " + cmd);
  };
  const r = ensureSshd({ file, run });
  assert.deepEqual(r, { gatewayports: "yes", clientaliveinterval: "0" });
  const after = readFileSync(file, "utf8");
  assert.ok(after.startsWith(base), "the rest of the file as it was");
  assert.match(after, /\nMatch User aegis-relay\n\tGatewayPorts no\n\tClientAliveInterval 20\n/);
  assert.equal(checks, 1); assert.deepEqual(reloads, ["ssh"]);
  // there already: never twice
  assert.equal(ensureSshd({ file, run }), null);
  assert.equal(readFileSync(file, "utf8"), after);
  // already right: nothing
  writeFileSync(file, base); eff = "gatewayports no\nclientaliveinterval 15\n";
  assert.equal(ensureSshd({ file, run }), null);
  assert.equal(readFileSync(file, "utf8"), base);
  // sshd -t says no: taken back out
  eff = "gatewayports clientspecified\nclientaliveinterval 0\n"; bad = true;
  assert.equal(ensureSshd({ file, run }), null);
  assert.equal(readFileSync(file, "utf8"), base);
});

test("the standby's scripts: a refresh from the main host stops a clone that took over; the watcher asks the main host itself", () => {
  const setup = standbySetup({ remote: "/tmp/x.tgz", watch: { url: "https://aegis.example.com", host: "main", name: "main", sshPort: 22, user: "u", interval: 30, misses: 4 }, hasSystemd: true });
  for (const [name, src] of [["setup", setup], ["watch", WATCH], ["revive", REVIVE]]) {
    const f = join(tmp(), name + ".sh"); writeFileSync(f, src);
    execFileSync("bash", ["-n", f]);
  }
  assert.match(setup, /the clone here had taken over: stopped it/);
  assert.doesNotMatch(setup, /left it as it is/);
  assert.match(setup, /systemctl --user restart aegis-standby\.service/, "the new watcher runs, not the old one");
  assert.match(WATCH, /"\$taken" = 1 \] && tcp "\$MAIN_HOST"[\s\S]*already up[\s\S]*stop_clone/);
});
