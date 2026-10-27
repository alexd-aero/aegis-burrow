// Administrator (root) access for addon scripts (Weft requires.root, burrow/root.mjs):
// the manifest rules, the per-job token store, the askpass route and helper,
// and the job's environment. sudo itself is never run here: RootAccess takes
// a fake one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "burrow-test-home-"));
process.env.AEGIS_RESCUE_SETTLE_MS = "1";                                   // rescue: no settling pauses
const A = await import("../burrow/addons.mjs");
const R = await import("../burrow/root.mjs");

const SECRET = "hunter2 correct-horse $(id) 'q\"";
const tmp = () => mkdtempSync(join(tmpdir(), "burrow-root-"));
function addon(root, manifest = {}, files = {}) {
  mkdirSync(root, { recursive: true });
  const m = { spec: 1, id: "rooty", name: "Rooty", version: "1.0.0", scripts: { install: "install.sh", uninstall: "uninstall.sh" }, ...manifest };
  writeFileSync(join(root, "forge-addon.json"), JSON.stringify(m));
  for (const [n, body] of Object.entries({ "install.sh": "echo installed\n", "uninstall.sh": "echo gone\n", ...files })) writeFileSync(join(root, n), body);
  return root;
}
// A sudo that never runs: passwordless or not, and which password it takes.
function fakeSudo({ passwordless = false, password = SECRET, missing = false, notAllowed = false } = {}) {
  const calls = [];
  const sudo = async (args, { input } = {}) => {
    calls.push({ args, input });
    if (missing) return { code: 127, out: "", err: "spawn sudo ENOENT", missing: true };
    if (args.includes("-n")) return passwordless ? { code: 0, out: "", err: "" } : { code: 1, out: "", err: "sudo: a password is required\n" };
    if (args.includes("-S")) {
      if (input !== password + "\n") return { code: 1, out: "", err: "Sorry, try again.\nsudo: no password was provided\nsudo: 1 incorrect password attempt\n" };
      if (notAllowed) return { code: 1, out: "", err: "rasp is not in the sudoers file.\n" };
      return { code: 0, out: "", err: "" };
    }
    return { code: 1, out: "", err: "?" };
  };
  return { sudo, calls };
}
const host = (dir, root, extra = {}) => new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.33.0", log: () => {}, root, ...extra });
const waitJob = async (H, j) => { for (let i = 0; i < 1200 && H.job(j.id).state === "running"; i++) await new Promise((r) => setTimeout(r, 50)); return H.job(j.id); };

test("manifest: requires.root is the reason (text ≤ 200), an action's root is a boolean", () => {
  const d = addon(tmp(), { requires: { root: "  Installs and configures Postfix and OpenDKIM " },
                           actions: [{ id: "keys", label: "Rotate keys", script: "install.sh", root: true }, { id: "look", label: "Look", script: "install.sh" }] });
  const m = A.loadManifest(d);
  assert.equal(m.requires.root, "Installs and configures Postfix and OpenDKIM");
  assert.equal(m.actions[0].root, true);
  assert.equal(m.actions[1].root, false);
  assert.equal(A.loadManifest(addon(tmp())).requires.root, "", "no requires.root: nothing needs root");
  for (const [bad, msg] of [[true, /requires\.root must be text/], [1, /requires\.root must be text/], ["", /requires\.root must be text/], ["   ", /requires\.root must be text/],
                            [["x"], /requires\.root must be text/], ["x".repeat(201), /longer than 200/]]) {
    assert.throws(() => A.loadManifest(addon(tmp(), { requires: { root: bad } })), (e) => e instanceof A.AddonError && msg.test(e.message), JSON.stringify(bad).slice(0, 20));
  }
  assert.ok(A.loadManifest(addon(tmp(), { requires: { root: "x".repeat(200) } })));
  for (const bad of ["yes", 1, "true", {}]) {
    assert.throws(() => A.loadManifest(addon(tmp(), { actions: [{ id: "keys", label: "Keys", script: "install.sh", root: bad }] })), /actions\.keys\.root must be true or false/);
  }
});

test("token store: in memory, per job, expires, dropped", () => {
  let now = 1000;
  const ra = new R.RootAccess({ sudo: fakeSudo().sudo, guard: () => null, now: () => now, ttl: 60e3 });
  const t = ra.issue(SECRET);
  assert.match(t, /^[0-9a-f]{64}$/);
  assert.equal(ra.get(t), SECRET);
  assert.equal(ra.get(t.replace(/.$/, (c) => (c === "0" ? "1" : "0"))), null, "a near miss is nothing");
  assert.equal(ra.get("nope"), null);
  assert.equal(ra.get(undefined), null);
  const p = ra.issue(null);
  assert.equal(ra.get(p), null, "passwordless: a token with no password");
  assert.ok(ra.has(p));
  now += 60e3;
  assert.equal(ra.get(t), null, "expired");
  assert.equal(ra.tokens.has(t), false, "and gone");
  const u = ra.issue("x");
  ra.drop(u);
  assert.equal(ra.get(u), null);
  ra.issue("y"); now += 61e3; ra.sweep();
  assert.equal(ra.tokens.size, 0, "the sweeper takes what expired");
  ra.stop();
  assert.equal(R.TOKEN_TTL, 3600e3, "an hour at most");
});

test("askpass route: answers only a live token, only POST, as text", async () => {
  const ra = new R.RootAccess({ sudo: fakeSudo().sudo, guard: () => null });
  const t = ra.issue(SECRET), p = ra.issue(null);
  const ask = (method, path, body) => ra.route(method, path, async () => body);
  assert.equal(await ask("GET", "/elsewhere"), null, "not its route");
  assert.equal((await ask("GET", "/askpass", { token: t })).status, 405);
  assert.equal((await ask("GET", `/askpass/${t}`)).status, 405, "never in a URL");
  for (const bad of [undefined, "", "x", t.toUpperCase(), t + "0", { t }, 42]) assert.equal((await ask("POST", "/askpass", { token: bad })).status, 404, String(bad));
  assert.equal((await ask("POST", "/askpass", { token: p })).status, 404, "passwordless: nothing to hand out");
  const ok = await ask("POST", "/askpass", { token: t });
  assert.equal(ok.status, 200);
  assert.equal(ok.body, SECRET + "\n");
  assert.match(ok.headers["Content-Type"], /text\/plain/);
  ra.drop(t);
  assert.equal((await ask("POST", "/askpass", { token: t })).status, 404, "a finished job's token");
  const bj = await ra.route("POST", "/askpass", async () => { throw new Error("bad JSON"); });
  assert.equal(bj.status, 400);
  ra.stop();
});

test("sudo checks: passwordless, a password, a wrong one, none at all, a sandbox", async () => {
  let f = fakeSudo({ passwordless: true });
  let ra = new R.RootAccess({ sudo: f.sudo, guard: () => null });
  assert.deepEqual(await ra.check(), { sudo: true, passwordless: true, why: null });
  assert.deepEqual(f.calls[0].args, ["-k", "-n", "true"], "-k: never a cached credential");
  await ra.check();
  assert.equal(f.calls.length, 1, "cached a minute");

  f = fakeSudo();
  ra = new R.RootAccess({ sudo: f.sudo, guard: () => null });
  assert.equal((await ra.check()).passwordless, false);
  await assert.rejects(ra.validate("wrong"), (e) => e instanceof R.RootError && e.status === 403 && e.extra.badPassword);
  assert.deepEqual(f.calls.at(-1).args, ["-S", "-k", "-p", "", "-v"]);
  assert.equal(f.calls.at(-1).input, "wrong\n", "the password goes on stdin");
  assert.ok(f.calls.every((c) => !c.args.some((a) => a.includes("wrong"))), "never in argv");
  assert.deepEqual(await ra.validate(SECRET), { ok: true });
  await assert.rejects(ra.validate(""), /Type your password/);
  await assert.rejects(ra.validate("a\nb"), /isn't a password/);
  for (let i = 0; i < 5; i++) await ra.validate("no").catch(() => {});
  await assert.rejects(ra.validate(SECRET), (e) => e.status === 429, "too many wrong ones: a pause");

  ra = new R.RootAccess({ sudo: fakeSudo({ notAllowed: true }).sudo, guard: () => null });
  await assert.rejects(ra.validate(SECRET), (e) => e.extra.noSudo && /isn't allowed to use sudo/.test(e.message));
  ra = new R.RootAccess({ sudo: fakeSudo({ missing: true }).sudo, guard: () => null });
  assert.equal((await ra.check()).sudo, false);
  f = fakeSudo({ passwordless: true });
  ra = new R.RootAccess({ sudo: f.sudo, guard: () => "Aegis runs with NoNewPrivileges (its systemd unit), so nothing it starts can use sudo" });
  const c = await ra.check();
  assert.equal(c.sudo, false);
  assert.match(c.why, /NoNewPrivileges/);
  assert.equal(f.calls.length, 0, "a sandbox is known without asking sudo");

  // the sandbox check reads /proc: NoNewPrivs, or a read-only /etc
  const d = tmp();
  writeFileSync(join(d, "status"), "Name:\tnode\nNoNewPrivs:\t1\n");
  writeFileSync(join(d, "mi"), "22 1 0:1 / / rw,relatime - ext4 /dev/x rw\n");
  assert.match(R.sandboxed({ status: join(d, "status"), mountinfo: join(d, "mi") }), /NoNewPrivileges/);
  writeFileSync(join(d, "status"), "NoNewPrivs:\t0\n");
  assert.equal(R.sandboxed({ status: join(d, "status"), mountinfo: join(d, "mi") }), null);
  writeFileSync(join(d, "mi"), "22 1 0:1 / / rw,relatime - ext4 /dev/x rw\n40 22 0:1 /etc /etc ro,nosuid - ext4 /dev/x rw\n41 22 0:1 /home /home rw - ext4 /dev/x rw\n");
  assert.match(R.sandboxed({ status: join(d, "status"), mountinfo: join(d, "mi") }), /read-only/);
  writeFileSync(join(d, "mi"), "22 1 0:1 / / ro,relatime - ext4 /dev/x rw\n");
  assert.match(R.sandboxed({ status: join(d, "status"), mountinfo: join(d, "mi") }), /read-only/);
  rmSync(d, { recursive: true });
});

test("a root job: asked first; ADDON_ROOT, the token and SUDO_ASKPASS in its env, never the password; the token dies with the job", async () => {
  const dir = tmp(), f = fakeSudo();
  const ra = new R.RootAccess({ sudo: f.sudo, guard: () => null });
  // a control socket answering /askpass the way server.mjs does, so the helper really runs
  const sock = join(dir, "c.sock");
  const srv = createServer(async (req, res) => {
    let d = ""; for await (const x of req) d += x;
    const r = await ra.route(req.method, req.url, async () => JSON.parse(d || "{}"));
    res.writeHead(r.status, r.headers || { "Content-Type": "application/json" });
    res.end(r.body ?? JSON.stringify(r.json));
  });
  await new Promise((ok) => srv.listen(sock, ok));
  const notices = [];
  const H = host(dir, ra, { notify: (n) => notices.push(n), env: () => ({ BURROW_SOCKET: sock, BURROW_NODE: process.execPath }) });
  const src = addon(tmp(), { requires: { root: "Configures Postfix" } }, {
    "install.sh": 'env > "$ADDON_DATA/env.txt"\n"$SUDO_ASKPASS" "[sudo] password:" > "$ADDON_DATA/askpass.out" && echo askpass-ok\necho "root=$ADDON_ROOT"\n',
  });
  await H.add(src);
  assert.equal((await H.list())[0].root.reason, "Configures Postfix", "the listing says so (for the chip)");

  // nobody asked: an automatic path never runs it, and the bell says so
  assert.throws(() => H.install("rooty", {}), /needs administrator \(root\) access to install: Configures Postfix/);
  assert.equal(notices.length, 1);
  assert.match(notices[0].title, /Rooty needs administrator access to install/);
  assert.equal(H.jobs.size, 0, "nothing ran");

  const info = await H.rootInfo("rooty");
  assert.equal(info.needsRoot, true);
  assert.equal(info.needs.install, true);
  assert.equal(info.passwordless, false);
  await assert.rejects(H.rootGrant("rooty", "install", {}), (e) => e.status === 428 && e.extra.needsRoot && e.extra.passwordless === false && e.extra.reason === "Configures Postfix");
  await assert.rejects(H.rootGrant("rooty", "install", { password: "nope" }), (e) => e.status === 403 && e.extra.badPassword);
  assert.equal(ra.tokens.size, 0, "a wrong password gets no token");

  const grant = await H.rootGrant("rooty", "install", { password: SECRET });
  assert.equal(ra.tokens.size, 1);
  const job = await waitJob(H, H.runOp("install", "rooty", {}, grant));
  assert.equal(job.state, "done", job.error);
  const data = join(dir, "addons", "rooty", "data");
  const env = Object.fromEntries(readFileSync(join(data, "env.txt"), "utf8").split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  assert.equal(env.ADDON_ROOT, "1");
  assert.match(env.ADDON_ASKPASS_TOKEN, /^[0-9a-f]{64}$/);
  assert.equal(env.SUDO_ASKPASS, R.ASKPASS);
  assert.ok(existsSync(R.ASKPASS), "the helper ships in bin/");
  assert.equal(env.FORGE_ADDON_ASKPASS_TOKEN, undefined, "no FORGE_ twin for the token");
  assert.ok(!readFileSync(join(data, "env.txt"), "utf8").includes("hunter2"), "the password is never in the environment");
  assert.ok(job.lines.some((l) => l.line === "askpass-ok"), job.lines.map((l) => l.line).join("\n"));
  assert.equal(readFileSync(join(data, "askpass.out"), "utf8"), SECRET + "\n", "the helper got it over the socket");
  assert.ok(!job.lines.some((l) => l.line.includes("hunter2")), "nor in the job's output");
  assert.ok(!JSON.stringify(H.job(job.id).view(0)).includes(env.ADDON_ASKPASS_TOKEN), "nor the token in the job's view");
  for (const fl of [join(dir, "addons.json"), ...readdirSync(data).filter((x) => x !== "askpass.out").map((x) => join(data, x))]) {
    assert.ok(!readFileSync(fl, "utf8").includes("hunter2"), `${fl} has no password`);
  }
  assert.equal(ra.tokens.size, 0, "the job ended: its token is gone");
  assert.equal(ra.get(env.ADDON_ASKPASS_TOKEN), null);

  // the helper with a dead token, and through BURROW_NODE when there is no curl
  const helper = (token, path = process.env.PATH) => new Promise((ok) => {
    const p = spawn("/bin/sh", [R.ASKPASS, "prompt"], { env: { PATH: path, BURROW_SOCKET: sock, BURROW_NODE: process.execPath, ADDON_ASKPASS_TOKEN: token } });
    let out = ""; p.stdout.on("data", (x) => (out += x)); p.on("close", (code) => ok({ code, out }));
  });
  assert.deepEqual(await helper(env.ADDON_ASKPASS_TOKEN), { code: 1, out: "" }, "a finished job's token: exit 1");
  assert.equal((await helper("not-a-token")).code, 1);
  const live = ra.issue("from-node");
  const empty = tmp();
  assert.deepEqual(await helper(live, empty), { code: 0, out: "from-node\n" }, "no curl on PATH: BURROW_NODE asks");
  ra.drop(live);

  // a non-root job: none of it, even when Aegis's own environment had some
  process.env.SUDO_ASKPASS = "/tmp/evil"; process.env.ADDON_ASKPASS_TOKEN = "f".repeat(64);
  const e2 = H.env(H.get("rooty"), "/x", "/y");
  delete process.env.SUDO_ASKPASS; delete process.env.ADDON_ASKPASS_TOKEN;
  assert.equal(e2.ADDON_ROOT, "0");
  assert.equal(e2.SUDO_ASKPASS, undefined);
  assert.equal(e2.ADDON_ASKPASS_TOKEN, undefined);

  // uninstall needs it too; a busy refusal drops the grant
  const g2 = await H.rootGrant("rooty", "uninstall", { password: SECRET });
  const j2 = H.runOp("uninstall", "rooty", { keep_data: true }, g2);
  const g3 = await H.rootGrant("rooty", "uninstall", { password: SECRET });
  assert.throws(() => H.runOp("uninstall", "rooty", {}, g3), /busy/);
  assert.equal(ra.get(g3.token), null, "a job that never started takes its token with it");
  assert.equal((await waitJob(H, j2)).state, "done");
  assert.equal(ra.tokens.size, 0);
  srv.close(); ra.stop();
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true }); rmSync(empty, { recursive: true });
});

test("passwordless sudo: a grant without a password; root actions; the watchdog and rescue never run root", async () => {
  const dir = tmp(), ra = new R.RootAccess({ sudo: fakeSudo({ passwordless: true }).sudo, guard: () => null });
  const notices = [];
  const H = host(dir, ra, { notify: (n) => notices.push(n) });
  const src = addon(tmp(), { id: "act", scripts: { install: "install.sh", status: "status.sh" },
                             actions: [{ id: "start", label: "Start", script: "start.sh", root: true }, { id: "look", label: "Look", script: "look.sh" }] },
                    { "status.sh": 'echo \'{"state":"stopped"}\'\n', "start.sh": 'echo "root=$ADDON_ROOT"\n', "look.sh": 'echo "root=$ADDON_ROOT"\n' });
  await H.add(src);
  assert.equal(await H.rootGrant("act", "install"), null, "install doesn't need root here");
  assert.equal((await waitJob(H, H.install("act", {}))).state, "done");
  const info = await H.rootInfo("act");
  assert.deepEqual(info.needs.actions, ["start"]);
  assert.equal(info.start, "start");
  assert.equal(info.passwordless, true);
  assert.match(info.reason, /"Start" needs administrator access/);
  assert.equal((await waitJob(H, H.action("act", "look"))).lines.at(-1).line, "root=0");
  assert.throws(() => H.action("act", "start"), /needs administrator \(root\) access to run "Start"/);
  const g = await H.rootGrant("act", "action", { action: "start" });
  assert.ok(g.token, "passwordless: a grant straight away (the UI still asks to continue)");
  assert.equal(ra.get(g.token), null, "with no password behind it");
  assert.equal((await waitJob(H, H.runOp("action", "act", { action: "start" }, g))).lines.at(-1).line, "root=1");
  // the watchdog's automatic start: refused, on the bell
  H.patch("act", { autoRestart: true });
  assert.throws(() => H.startDown("act"), /needs administrator/);
  assert.ok(notices.some((n) => n.key === "root-act-action"));
  // rescue skips the root start action and says why in its report
  const rj = await waitJob(H, H.rescue("act"));
  assert.ok(rj.lines.some((l) => /needs administrator \(root\) access/.test(l.line)) || readFileSync(join(dir, "addons", "act", "rescue", rj.result.file), "utf8").includes("needs administrator (root) access"));
  ra.stop();
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});

test("update: a new version that needs root changes nothing until it's given", async () => {
  const dir = tmp(), ra = new R.RootAccess({ sudo: fakeSudo().sudo, guard: () => null });
  const H = host(dir, ra, { notify: () => {} });
  const src = addon(tmp(), { id: "grow", scripts: { install: "install.sh" } }, { "install.sh": 'echo "v=$ADDON_VERSION root=$ADDON_ROOT"\n' });
  await H.add(src);
  assert.equal((await waitJob(H, H.install("grow", {}))).state, "done");
  assert.equal(H.rootNeed(H.get("grow"), "update"), "");
  addon(src, { id: "grow", version: "2.0.0", scripts: { install: "install.sh" }, requires: { root: "Now runs a mail server" } }, { "install.sh": 'echo "v=$ADDON_VERSION root=$ADDON_ROOT"\n' });
  const j = await waitJob(H, H.update("grow"));
  assert.equal(j.state, "error");
  assert.match(j.error, /2\.0\.0 needs administrator \(root\) access to update: Now runs a mail server\. Nothing changed/);
  assert.equal(H.get("grow").manifest.version, "1.0.0", "the old code is still in place");
  assert.equal(H.rootNeed(H.get("grow"), "update"), "Now runs a mail server", "the next try asks");
  assert.equal(H.updates().length, 0);
  const g = await H.rootGrant("grow", "update", { password: SECRET });
  const j2 = await waitJob(H, H.runOp("update", "grow", {}, g));
  assert.equal(j2.state, "done", j2.error);
  assert.equal(j2.lines.at(-1).line, "v=2.0.0 root=1");
  assert.equal(ra.tokens.size, 0);
  ra.stop();
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});
