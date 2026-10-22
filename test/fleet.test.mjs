// Machine management: the registry, the link command, what a probe says, and
// that every script we paste into a far machine's bash is valid shell.
// Nothing here reaches a real machine: ssh is never called (verify is stubbed
// where a test would otherwise dial out), and every path is a temp dir.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "aegis-fleet-test-"));
process.env.HOME = home;
process.env.AEGIS_HOME = join(home, "aegis");
mkdirSync(join(home, "aegis", "data"), { recursive: true });

const F = await import("../aegis/fleet.mjs");
const OPS = await import("../aegis/fleet-ops.mjs");
const { Settings, writeJson } = await import("../aegis/config.mjs");

let n = 0;
function fleet() {
  const dir = join(home, `f${++n}`);
  const settings = new Settings();
  const f = new F.Fleet({ settings, dir, file: join(dir, "fleet.json"), log: () => {}, version: "test",
                          notify: () => {}, dashboards: () => ["pi.example", "other.example"] });
  f.setEnabled(true);
  return f;
}
const shOk = (body, shell = "bash") => spawnSync(shell, ["-n"], { input: body }).status === 0;

test("off until it is switched on", () => {
  const f = fleet();
  f.setEnabled(false);
  assert.equal(f.enabled(), false);
  assert.throws(() => f.need(), F.FleetError);
  assert.throws(() => f.need(), /Settings/);
  f.setEnabled(true);
  assert.equal(f.enabled(), true);
});

test("the link command only ever points at one of our own addresses", async () => {
  const f = fleet();
  const inv = await f.invite({ base: "https://pi.example", label: "forge" });
  assert.match(inv.command, /^curl -fsSL "https:\/\/pi\.example\/__gate\/fleet\/join\?t=[\w-]{20,}" \| sh$/);
  assert.ok(inv.publicKey.startsWith("ssh-ed25519 "));
  assert.ok(f.pending(inv.token), "the token is good until it is used");
  assert.equal(f.pending("nope"), null);
  await assert.rejects(() => f.invite({ base: "https://evil.example" }), /not one of this gate's addresses/);
  await assert.rejects(() => f.invite({ base: "ftp://pi.example" }), /http or https/);
  assert.equal(await f.invite({ base: "http://192.168.1.9:4310" }).then((i) => i.base), "http://192.168.1.9:4310");
});

test("the script it hands out is valid sh, carries our key, and nothing else", async () => {
  const f = fleet();
  const inv = await f.invite({ base: "https://pi.example" });
  const s = f.joinScript(inv.token, inv.base);
  assert.ok(shOk(s, "sh"), "the join script must parse as plain sh");
  assert.ok(s.includes(inv.publicKey), "it carries the public key");
  assert.ok(!s.includes("id_ed25519\n") && !/PRIVATE KEY/.test(s), "and never the private one");
  assert.match(s, /authorized_keys/);
  assert.match(s, /__gate\/fleet\/claim/);
});

test("a machine claims itself once, with the addresses it gave", async () => {
  const f = fleet();
  f.verify = async (id) => f.get(id);                        // no ssh in tests
  const inv = await f.invite({ base: "https://pi.example" });
  const r = await f.claim(inv.token, { hostname: "forge-claude", user: "alex", port: 2222,
                                       addresses: "100.66.153.83 192.168.1.40 ; rm -rf /", os: "Ubuntu", arch: "x86_64" }, "203.0.113.9");
  assert.ok(r.ok);
  const m = f.get(r.id);
  assert.equal(m.user, "alex");
  assert.equal(m.port, 2222);
  assert.deepEqual(m.candidates, ["100.66.153.83", "192.168.1.40", "203.0.113.9", "forge-claude"]);
  assert.ok(!m.candidates.includes("rm"), "a word from a mangled list is not an address");
  assert.equal(f.pending(inv.token), null, "the token is spent");
  await assert.rejects(() => f.claim(inv.token, { hostname: "x", user: "alex" }, "203.0.113.9"), /expired/);
});

test("a claim without a usable user or address is refused", async () => {
  const f = fleet();
  f.verify = async (id) => f.get(id);
  const bad = async (facts, ip = null) => {
    const inv = await f.invite({ base: "https://pi.example" });
    await assert.rejects(() => f.claim(inv.token, facts, ip), F.FleetError);
  };
  await bad({ hostname: "x", user: "root; cat /etc/shadow", addresses: "10.0.0.1" }, "203.0.113.9");
  await bad({ hostname: "", user: "alex", addresses: "not an address!" });
  await bad({ hostname: "", user: "alex", addresses: "" });
  // nothing of its own, but we saw where it called from: that is address enough
  const inv = await f.invite({ base: "https://pi.example" });
  const r = await f.claim(inv.token, { hostname: "", user: "alex", addresses: "" }, "203.0.113.9");
  assert.equal(f.get(r.id).address, "203.0.113.9");
});

test("by hand: an address and a user, checked before it is kept", async () => {
  const f = fleet();
  f.verify = async (id) => f.get(id);
  const r = await f.addManual({ address: "https://forge.example.com/x", user: "alex", port: 22, name: "Forge" });
  assert.equal(f.get(r.id).address, "forge.example.com");
  await assert.rejects(() => f.addManual({ address: "what is this", user: "alex" }), /address or hostname/);
  await assert.rejects(() => f.addManual({ address: "10.0.0.1", user: "Alex Smith" }), /user name/);
  // one that cannot be reached is not left behind
  const f2 = fleet();
  f2.verify = async () => { throw new F.FleetError("nope"); };
  await assert.rejects(() => f2.addManual({ address: "10.0.0.1", user: "alex" }), /nope/);
  assert.equal(f2.list().length, 0);
});

test("a probe becomes specs, usage and the apps we know by name", () => {
  const raw = `
==host==
hostname=forge-claude
user=alex
uid=1000
home=/home/alex
uptime=90061.5
==os==
kernel=6.8.0
arch=aarch64
pretty=Ubuntu 24.04.5 LTS
distro=ubuntu
model=Raspberry Pi 5 Model B
==cpu==
cores=4
model=Cortex-A76
load=0.80 0.40 0.30
temp=49000
==mem==
memtotal=16384000
memavailable=8192000
==disk==
/|488000000|100000000|388000000
==net==
100.66.153.83
192.168.1.40
==ssh==
port=2222
listening=22,80,443
==docker==
termix|ghcr.io/lukegus/termix:latest|Up 9 hours|127.0.0.1:4300->4300/tcp
__ok__
==units==
bulwark.service
user:selkies-forge.service
user:forge-addon-hello.service
==apps==
--/home/alex/.config/aegis/aegis.json
{"version":"2.23.3","home":"/home/alex/.local/share/aegis","cli":"/x/bin/aegis","dashboard":"https://a.example/","service":{"name":"aegis.service","scope":"user"}}
--/home/alex/.config/aegis/integrations/selkies-forge.json
{"version":"1.10.11","url":"http://100.66.153.83:8787/","home":"/home/alex/.selkies-forge"}
--dir:bulwark=/home/alex/.local/share/bulwark
==end==
`;
  const p = F.readProbe(raw);
  assert.equal(p.host.hostname, "forge-claude");
  assert.equal(p.os.pretty, "Ubuntu 24.04.5 LTS");
  assert.equal(p.cpu.cores, 4);
  assert.equal(p.cpu.tempC, 49);
  assert.deepEqual(p.cpu.load, [0.8, 0.4, 0.3]);
  assert.equal(p.mem.total, 16384000 * 1024);
  assert.equal(p.mem.used, (16384000 - 8192000) * 1024);
  assert.equal(p.disks[0].mount, "/");
  assert.deepEqual(p.addresses, ["100.66.153.83", "192.168.1.40"]);
  assert.equal(p.ssh.port, 2222);
  assert.equal(p.docker.length, 1);
  assert.equal(p.docker[0].name, "termix");
  const ids = p.apps.map((a) => a.id);
  assert.deepEqual(ids, ["aegis-burrow", "selkies-forge", "bulwark", "termix"]);
  const aegis = p.apps[0];
  assert.equal(aegis.version, "2.23.3");
  assert.equal(aegis.service, "aegis.service");
  assert.equal(aegis.scope, "user");
  assert.equal(p.apps[1].home, "/home/alex/.selkies-forge");
  // an addon's unit must not be mistaken for the Forge's own
  assert.equal(p.apps[1].service, "user:selkies-forge.service");
  assert.throws(() => F.readProbe("nothing like a probe"), /not with what we asked for/);
});

test("the dashboard's view of a machine, and where an app lives", async () => {
  const f = fleet();
  f.verify = async (id) => f.get(id);
  const inv = await f.invite({ base: "https://pi.example" });
  const { id } = await f.claim(inv.token, { hostname: "b", user: "alex", port: 22, addresses: "10.0.0.2" }, null);
  f.patch(id, { lastSeen: Date.now(), probedAt: Date.now(), probe: { cpu: { cores: 4, load: [2], tempC: null }, os: {}, mem: { total: 8, used: 4 },
                 disks: [{ mount: "/", total: 10, used: 5 }], apps: [{ id: "selkies-forge", name: "Selkies Forge", version: "1.10", url: "http://10.0.0.2:8787/" }],
                 addresses: [], host: {}, ssh: {}, docker: null, units: [] } });
  const card = f.view().machines[0];
  assert.equal(card.up, true);
  assert.equal(card.specs.cores, 4);
  assert.equal(card.usage.load, 2);
  assert.deepEqual(f.whereIs("selkies-forge"), [{ machine: id, name: "b", address: "10.0.0.2", url: "http://10.0.0.2:8787/", version: "1.10", up: true }]);
  assert.deepEqual(f.whereIs("termix"), []);
  assert.equal(f.view().hub.role, "hub");
});

test("forgetting one, keeping its key", async () => {
  const f = fleet();
  f.verify = async (id) => f.get(id);
  const r = await f.addManual({ address: "10.0.0.3", user: "alex" });
  const gone = await f.forget(r.id, false);          // false: don't ssh anywhere to take the key off
  assert.equal(gone.ok, true);
  assert.equal(f.list().length, 0);
  assert.throws(() => f.get(r.id), /No such machine/);
});

test("two jobs never run on one machine at a time", () => {
  const f = fleet();
  let release;
  const held = new Promise((r) => { release = r; });
  f.start("test", "First", "m-1", () => held);
  assert.throws(() => f.start("test", "Second", "m-1", async () => {}), /busy/);
  assert.throws(() => f.start("test", "Third", ["m-0", "m-1"], async () => {}), /busy/, "a swap waits for either side");
  const other = f.start("test", "Elsewhere", "m-2", async () => "ok");
  assert.equal(other.state, "running");
  release();
});

test("every script we paste into a far machine's bash parses", () => {
  assert.ok(shOk(F.PROBE), "the probe");
  assert.ok(shOk(OPS.WATCH), "the standby watcher");
  assert.ok(shOk(OPS.REVIVE), "the restart script");
  assert.ok(shOk(OPS.HELPERS), "the stop/start helpers");
  for (const [id, app] of Object.entries(OPS.CATALOG)) {
    if (app.install) assert.ok(shOk(app.install), `${id}: install`);
    assert.ok(shOk(app.locate), `${id}: locate`);
  }
  const setup = (systemd) => OPS.standbySetup({ remote: "/tmp/c.tgz", hasSystemd: systemd,
    watch: { url: "https://pi.example", host: "pi", name: "pi", sshPort: 22, user: "alex", interval: 30, misses: 4 } });
  assert.ok(shOk(setup(true)), "the standby setup, with systemd");
  assert.ok(shOk(setup(false)), "the standby setup, without");
  // the watcher it writes has to parse on its own too
  const written = /cat > "\$D\/watch.sh" <<'WATCH'\n([\s\S]*?)\nWATCH/.exec(setup(true));
  assert.ok(written && shOk(written[1]), "the watcher, as the setup writes it");
});

test("shell quoting", () => {
  assert.equal(F.sq("plain"), "'plain'");
  assert.equal(F.sq("it's"), `'it'\\''s'`);
  assert.ok(shOk(`echo ${F.sq("; rm -rf / #")}`));
});

test("a takeover is read back, and says nothing about restarting a host that is down", () => {
  const DATA = join(process.env.AEGIS_HOME, "data");
  assert.equal(OPS.takeover(), null);
  writeJson(join(DATA, "takeover.json"), { at: 1700000000000, main: "pi", url: "https://pi.example",
                                           reason: "pi stopped answering (4 checks in a row)", mainReachable: false, attempts: 0 });
  const t = OPS.takeover();
  assert.equal(t.mainReachable, false);
  const said = [];
  OPS.takeoverNotice((src, nn) => said.push(nn));
  assert.equal(said.length, 1);
  assert.match(said[0].title, /went down/);
  assert.match(said[0].body, /not answering at all/);
  assert.ok(!/running the restart script on it/.test(said[0].body), "it must not claim to be restarting a host that is down");
  assert.equal(said[0].level, "critical");
  OPS.takeoverNotice((src, nn) => said.push(nn));
  assert.equal(said.length, 1, "the same state is only said once");

  writeJson(join(DATA, "takeover.json"), { at: 1700000000000, main: "pi", url: "https://pi.example",
                                           reason: "pi stopped answering", mainReachable: true, attempts: 3 });
  OPS.takeoverNotice((src, nn) => said.push(nn));
  assert.match(said[1].body, /running the restart script on it \(3 attempts so far\)/);

  writeJson(join(DATA, "takeover.json"), { at: 1700000000000, main: "pi", reason: "x", mainReachable: true, attempts: 3, handedBack: 1700000900000 });
  assert.equal(OPS.takeoverNotice(() => assert.fail("nothing to say once the main host is back")), null);
});

test("the key is made once, kept to this user, and the known_hosts is ours", async () => {
  const f = fleet();
  const pub = await f.publicKey();
  assert.equal(await f.publicKey(), pub, "the same key, not a new one");
  assert.ok(existsSync(f.keyPath()));
  const args = f.sshArgs({ port: 2222, user: "alex", address: "10.0.0.9" });
  assert.ok(args.includes("BatchMode=yes"), "never waits for a password");
  assert.ok(args.includes("IdentitiesOnly=yes"), "never offers another key of yours");
  assert.ok(args.some((a) => a.startsWith("UserKnownHostsFile=") && a.includes(f.dir)), "its own known_hosts");
  assert.equal(args.at(-1), "alex@10.0.0.9");
  assert.deepEqual(f.scpArgs({ port: 2222, user: "alex", address: "10.0.0.9" }).slice(-2), ["-P", "2222"]);
});

test("an addon's program installs like an app: its own steps over our link, then a note the next probe reads", async () => {
  const f = fleet();
  f.verify = async (id) => f.get(id);
  const r = await f.addManual({ address: "10.0.0.9", user: "alex", port: 2200, name: "Far" });
  const scripts = [];
  f.ssh = async (m, script, o = {}) => { scripts.push(script); o.onLine?.("from the machine"); return { code: 0, out: "ok", err: "" }; };
  f.probe = async () => {};
  let seen = null;
  const programs = new Map([["helper:thing", { name: "Thing", note: "A thing.", addon: "helper",
    install: async (machine, tools) => { seen = machine; tools.step("Doing it", 0.5); await tools.run("echo hi"); return { url: "https://thing.example/" }; } }]]);
  const job = OPS.install(f, r.id, "helper:thing", programs);
  assert.equal(job.label, "Installing Thing on Far");
  for (let i = 0; i < 50 && f.job(job.id).state === "running"; i++) await new Promise((res) => setTimeout(res, 10));
  const done = f.job(job.id).view();
  assert.equal(done.state, "done", done.error || "");
  assert.deepEqual(done.result, { app: "helper:thing", machine: r.id, url: "https://thing.example/" });
  assert.deepEqual([seen.address, seen.user, seen.port, seen.name], ["10.0.0.9", "alex", 2200, "Far"]);
  assert.ok(done.lines.some((l) => l.line === "from the machine"), "the machine's output is in the job");
  assert.equal(scripts[0], "echo hi");
  assert.match(scripts[1], /\.config\/aegis\/programs\/helper_thing\.json/);
  assert.ok(shOk(scripts[1]), "the note it leaves is valid shell");
  // a built-in app's id still means the built-in app, and an unknown one is refused
  assert.throws(() => OPS.install(f, r.id, "nothing:here", programs), /does not know/);
  // the probe reads that note back as an app on the machine
  const raw = `==host==\nhome=/h\n==apps==\n--prog:/h/.config/aegis/programs/helper_thing.json\n{"id":"helper:thing","name":"Thing","url":"https://thing.example/"}\n==end==\n`;
  assert.deepEqual(F.readProbe(raw).apps.map((a) => [a.id, a.name, a.url, a.program]), [["helper:thing", "Thing", "https://thing.example/", true]]);
  assert.ok(shOk(F.PROBE), "the probe, with the programs folder");
});

test("a machine is only down after several missed checks in a row, not after a quiet five minutes", async () => {
  const now = Date.now();
  assert.equal(F.isUp({ lastSeen: now - 30000, misses: 0 }, now), true);
  assert.equal(F.isUp({ lastSeen: now - 30000, misses: F.MISSES_DOWN - 1 }, now), true, "one slow answer is not down");
  assert.equal(F.isUp({ lastSeen: now - 30000, misses: F.MISSES_DOWN }, now), false);
  assert.equal(F.isUp({ lastSeen: null }, now), false);

  const f = fleet();
  f.setEnabled(true);
  f.verify = async (id) => f.get(id);
  const r = await f.addManual({ address: "10.0.0.9", user: "alex" });
  f.patch(r.id, { lastSeen: now });
  // the heartbeat's ssh fails (nothing at 10.0.0.9 in a test): misses add up, lastSeen is kept
  f.sshArgs = () => ["-o", "ConnectTimeout=1", "-o", "BatchMode=yes", "-p", "1", "nobody@127.0.0.1"];
  await f.beat();
  assert.equal(f.get(r.id).misses, 1);
  assert.equal(f.get(r.id).lastSeen, now, "a miss never wipes when it was last seen");
  assert.equal(f.cardOf(f.get(r.id)).up, true);
  await f.beat(); await f.beat();
  assert.equal(f.cardOf(f.get(r.id)).up, false);
  assert.ok(f.get(r.id).lastError);
});

test("the standby only counts the main gate itself, and never takes over a gate that still answers", () => {
  assert.match(OPS.WATCH, /__gate\/health/);
  assert.match(OPS.WATCH, /"standby":true/, "the clone's own answer is not the main being back");
  assert.match(OPS.WATCH, /already up"\*\) say .*not taking over/);
  assert.match(OPS.WATCH, /AEGIS_STANDBY=1/);
  const setup = OPS.standbySetup({ remote: "/tmp/c.tgz", hasSystemd: true,
    watch: { url: "https://pi.example", host: "pi", name: "pi", sshPort: 22, user: "alex", interval: 30, misses: 4 } });
  assert.ok(setup.indexOf("left it as it is") < setup.indexOf("tar -C"), "a running clone is never unpacked over");
});

test("Termix opens straight into a host's terminal, and nothing else rides along", () => {
  const q = (s) => F.termixQuery(new URLSearchParams(s));
  assert.equal(q("view=terminal&hostId=7"), "?view=terminal&hostId=7");
  assert.equal(q("view=terminal&hostId=7&next=//evil.example"), "?view=terminal&hostId=7");
  assert.equal(q("view=javascript:alert(1)&hostId=7"), "");
  assert.equal(q("view=terminal&hostId=7;rm"), "?view=terminal");
  assert.equal(q("hostId=7"), "", "a host with no view means nothing");
  assert.equal(q(""), "");
});

test("a machine's card carries what the panel needs: Termix's host id, the standby's state (no keys)", async () => {
  const f = fleet();
  f.setEnabled(true);
  f.verify = async (id) => f.get(id);
  const r = await f.addManual({ address: "10.0.0.5", user: "alex" });
  f.patch(r.id, { termix: { hostId: 12, at: 1, auth: "key" }, standby: true, standbyState: { at: 2, url: "https://pi.example", interval: 30, misses: 4, key: "ssh-ed25519 AAAA secret" } });
  const c = f.cardOf(f.get(r.id));
  assert.deepEqual(c.termix, { hostId: 12, at: 1 });
  assert.equal(c.standbyState.url, "https://pi.example");
  assert.ok(!JSON.stringify(c).includes("AAAA"), "the standby's key is not handed to the page");
});

test("a transfer refuses what it can't do before touching anything", () => {
  const f = fleet();
  f.setEnabled(true);
  assert.throws(() => OPS.transfer(f, "nope", "m-1", "m-2"), /does not know/);
  assert.throws(() => OPS.transfer(f, "aegis-burrow", "m-1", "m-2"), /cannot be moved/);
  assert.throws(() => OPS.transfer(f, "termix", "m-1", "m-1"), /two different/);
  assert.throws(() => OPS.transfer(f, "termix", "m-1", "m-2", { mode: "teleport" }), /move or a copy/);
});
