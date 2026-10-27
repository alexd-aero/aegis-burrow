// Root jobs run in the user's own terminal (2.35): the gate makes the job and
// hands its script over once (runspec); the CLI's runner (burrow/terminal.mjs)
// runs it, streams its lines back and reports its exit code; the gate then ends
// the job exactly as if it had run it. The API here is called in-process (the
// same methods the control socket routes call); bash runs for real, stdin closed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "burrow-test-home-"));
const A = await import("../burrow/addons.mjs");
const R = await import("../burrow/root.mjs");
const { runHere } = await import("../burrow/terminal.mjs");

const tmp = () => mkdtempSync(join(tmpdir(), "burrow-term-"));
function addon(root, manifest = {}, files = {}) {
  mkdirSync(root, { recursive: true });
  const m = { spec: 1, id: "mail", name: "Mail", version: "1.0.0", requires: { root: "Configures Postfix" },
              scripts: { install: "install.sh", uninstall: "uninstall.sh" }, ...manifest };
  writeFileSync(join(root, "forge-addon.json"), JSON.stringify(m));
  for (const [n, body] of Object.entries({ "install.sh": "echo installed\n", "uninstall.sh": "echo gone\n", ...files })) writeFileSync(join(root, n), body);
  return root;
}
// a gate that can't get root (sandboxed): the dashboard can't, the terminal can
const sandboxed = () => new R.RootAccess({ sudo: async () => { throw new Error("sudo must not run"); }, guard: () => "Aegis runs with NoNewPrivileges (its systemd unit), so nothing it starts can use sudo" });
const gate = (dir, extra = {}) => new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.35.0", log: () => {}, root: sandboxed(),
                                                  env: () => ({ BURROW_SOCKET: "/run/x.sock", BURROW_NODE: process.execPath, ADDON_HOST_URL: "https://dash.example/" }), ...extra });
// the control socket's routes, in-process
const api = (H) => async (method, path, body) => {
  const b = typeof body === "string" ? JSON.parse(body) : body || {};
  try {
    let m;
    if ((m = /^\/addons\/([a-z0-9-]+)\/runspec$/.exec(path))) return await H.terminalRun(m[1], b);
    if ((m = /^\/addons\/jobs\/([0-9a-f]{12})\/line$/.exec(path))) return H.terminalLines(m[1], b);
    if ((m = /^\/addons\/jobs\/([0-9a-f]{12})\/done$/.exec(path))) return H.terminalDone(m[1], b);
    if ((m = /^\/addons\/jobs\/([0-9a-f]{12})$/.exec(path))) return H.job(m[1]).view(0);
    throw new Error("no route " + path);
  } catch (e) { throw Object.assign(new Error(e.message), { status: e.status || 400 }); }
};
const quiet = { print: () => {}, raw: () => {}, stdin: "ignore", flushMs: 20, pollMs: 20 };
const waitJob = async (H, id) => { for (let i = 0; i < 400 && H.job(id).state === "running"; i++) await new Promise((r) => setTimeout(r, 25)); return H.job(id); };

test("install in the terminal: the gate can't get root, the terminal runs the script, the job ends as if the gate had", async () => {
  const dir = tmp(), H = gate(dir);
  const src = addon(tmp(), {}, { "install.sh": [
    'echo "root=$ADDON_ROOT adopt=$ADDON_ADOPT askpass=${SUDO_ASKPASS:-none} token=${ADDON_ASKPASS_TOKEN:-none} sock=$BURROW_SOCKET"',
    'echo "data=$ADDON_DATA"', "echo ::phase configuring postfix", "echo ::progress 60 halfway", 'echo "to stderr" >&2', "echo ::open http://127.0.0.1:8088/", "echo done-installing", ""].join("\n") });
  await H.add(src);
  // the dashboard: refused, with the command to type
  await assert.rejects(H.rootGrant("mail", "install", {}), (e) => e.extra.noSudo && e.extra.command === "aegis addons install mail" && /Run it in a terminal on this machine: aegis addons install mail/.test(e.message));
  const info = await H.rootInfo("mail");
  assert.equal(info.sudo, false); assert.equal(info.commands.install, "aegis addons install mail");
  const printed = [];
  process.env.SUDO_ASKPASS = "/should/not/pass"; process.env.ADDON_ASKPASS_TOKEN = "f".repeat(64);
  let r;
  try { r = await runHere({ call: api(H), op: "install", id: "mail", ...quiet, print: (s) => printed.push(s) }); }
  finally { delete process.env.SUDO_ASKPASS; delete process.env.ADDON_ASKPASS_TOKEN; }
  assert.equal(r.ran, true); assert.equal(r.code, 0);
  assert.equal(r.job.state, "done", r.job.error);
  assert.equal(r.job.terminal, true);
  const out = r.job.lines.map((l) => l.line);
  assert.ok(out.includes("root=1 adopt=0 askpass=none token=none sock=/run/x.sock"), out.join("\n"));
  assert.ok(out.includes("to stderr"), "stderr goes back too");
  assert.ok(out.includes("done-installing"));
  assert.ok(!out.some((l) => l.startsWith("::")), "directives are directives, not log lines");
  assert.equal(r.job.result.open_url, "http://127.0.0.1:8088/", "::open honoured");
  assert.ok(printed.some((l) => /configuring postfix/.test(l)), "the terminal shows the phase");
  const rec = H.get("mail");
  assert.equal(rec.installed, true); assert.equal(rec.installed_version, "1.0.0"); assert.equal(rec.open_url, "http://127.0.0.1:8088/");
  // the data folder is the gate's, not the terminal's idea
  assert.ok(out.includes(`data=${join(dir, "addons", "mail", "data")}`));
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});

test("the run spec: only for what needs root, the addon's own variables only, one job at a time; tokens, cancel, two hours", async () => {
  const dir = tmp(), H = gate(dir, { terminalTtl: 400 });
  const src = addon(tmp(), { actions: [{ id: "look", label: "Look", script: "look.sh" }, { id: "fix", label: "Fix", script: "look.sh", root: true }] }, { "look.sh": "echo look\n" });
  await H.add(src);
  await assert.rejects(H.terminalRun("mail", { op: "action", action: "look" }), /doesn't need root to run look: it runs in Aegis/);
  await assert.rejects(H.terminalRun("mail", { op: "nope" }), /op is install/);
  const s = await H.terminalRun("mail", { op: "install" });
  assert.match(s.token, /^[0-9a-f]{64}$/);
  assert.equal(s.script, join(dir, "addons", "mail", "repo", "install.sh"));
  assert.equal(s.cwd, join(dir, "addons", "mail", "repo"));
  assert.equal(s.env.ADDON_ROOT, "1"); assert.equal(s.env.FORGE_ADDON_ID, "mail"); assert.equal(s.env.BURROW_SOCKET, "/run/x.sock");
  for (const k of ["PATH", "HOME", "SUDO_ASKPASS", "ADDON_ASKPASS_TOKEN"]) assert.equal(s.env[k], undefined, `${k} is the terminal's own`);
  await assert.rejects(H.terminalRun("mail", { op: "install" }), /busy/, "one job at a time");
  assert.throws(() => H.terminalLines(s.job.id, { token: "0".repeat(64), lines: ["x"] }), (e) => e.status === 403);
  assert.throws(() => H.terminalDone(s.job.id, {}), (e) => e.status === 403);
  H.terminalLines(s.job.id, { token: s.token, lines: ["::progress 40 going", "a line"] });
  assert.equal(H.job(s.job.id).progress, 0.4);
  // cancelled in the dashboard: the terminal hears it (410) on its next line
  H.job(s.job.id).cancel();
  assert.throws(() => H.terminalLines(s.job.id, { token: s.token, lines: ["more"] }), (e) => e.status === 410);
  const j = await waitJob(H, s.job.id);
  assert.notEqual(j.state, "done");
  assert.equal(H.get("mail").installed, false, "nothing was marked installed");
  // a terminal that never reports back: the job ends after the limit (two hours; 400 ms here)
  const s2 = await H.terminalRun("mail", { op: "install" });
  const j2 = await waitJob(H, s2.job.id);
  assert.equal(j2.state, "error");
  assert.ok(j2.lines.some((l) => /never said it was done/.test(l.line)));
  assert.throws(() => H.terminalDone(s2.job.id, { token: s2.token, code: 0 }), (e) => e.status === 410, "too late");
  // a root action, in the terminal
  H.patch("mail", { installed: true, installed_version: "1.0.0" });
  const r = await runHere({ call: api(H), op: "action", id: "mail", body: { action: "fix" }, ...quiet });
  assert.equal(r.job.state, "done"); assert.ok(r.job.lines.some((l) => l.line === "look"));
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});

test("update in the terminal: the new version is staged, and only stays once its script succeeds", async () => {
  const dir = tmp(), H = gate(dir);
  const src = addon(tmp(), { scripts: { install: "install.sh", update: "update.sh", uninstall: "uninstall.sh" } }, { "update.sh": "echo updated-1\n" });
  await H.add(src);
  assert.equal((await runHere({ call: api(H), op: "install", id: "mail", ...quiet })).job.state, "done");
  // v2, whose update fails
  addon(src, { version: "2.0.0", scripts: { install: "install.sh", update: "update.sh", uninstall: "uninstall.sh" } }, { "update.sh": 'echo "v=$ADDON_VERSION update=$ADDON_UPDATE"; exit 3\n' });
  let r = await runHere({ call: api(H), op: "update", id: "mail", ...quiet });
  assert.equal(r.code, 3); assert.equal(r.job.state, "error");
  assert.match(r.job.error, /update script failed \(exit 3\)/);
  assert.ok(r.job.lines.some((l) => l.line === "v=2.0.0 update=1"), "it ran the new version's script");
  assert.equal(H.get("mail").manifest.version, "1.0.0", "the old version is back in the registry");
  assert.equal(readFileSync(join(dir, "addons", "mail", "repo", "update.sh"), "utf8"), "echo updated-1\n", "and on disk");
  assert.ok(!existsSync(join(dir, "addons", "mail", "repo.old")));
  // v2 again, now it works
  addon(src, { version: "2.0.0", scripts: { install: "install.sh", update: "update.sh", uninstall: "uninstall.sh" } }, { "update.sh": 'echo "v=$ADDON_VERSION"\n' });
  r = await runHere({ call: api(H), op: "update", id: "mail", ...quiet });
  assert.equal(r.job.state, "done", r.job.error);
  assert.equal(H.get("mail").manifest.version, "2.0.0"); assert.equal(H.get("mail").installed_version, "2.0.0");
  assert.ok(!existsSync(join(dir, "addons", "mail", "repo.old")), "the old copy goes once it worked");
  // uninstall, in the terminal, keeping nothing
  writeFileSync(join(dir, "addons", "mail", "data", "x"), "1");
  r = await runHere({ call: api(H), op: "uninstall", id: "mail", body: { keep_data: false }, ...quiet });
  assert.equal(r.job.state, "done");
  assert.equal(H.get("mail").installed, false);
  assert.ok(!existsSync(join(dir, "addons", "mail", "data", "x")));
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});

test("the runner: a script that dies by a signal, and a cancel from the dashboard stops the script here", async () => {
  const dir = tmp(), H = gate(dir);
  const src = addon(tmp(), {}, { "install.sh": "echo start\nsleep 30\necho never\n" });
  await H.add(src);
  const p = runHere({ call: api(H), op: "install", id: "mail", ...quiet });
  let job;
  for (let i = 0; i < 200 && !job; i++) { job = [...H.jobs.values()].find((j) => j.state === "running" && j.lines.some((l) => l.line === "start")); await new Promise((r) => setTimeout(r, 25)); }
  assert.ok(job, "the first line arrived while it runs");
  job.cancel();
  const t0 = Date.now();
  const r = await p;
  assert.ok(Date.now() - t0 < 5000, "the script was stopped, not waited for");
  assert.ok(r.stopped); assert.notEqual(r.job.state, "done");
  assert.ok(!r.job.lines.some((l) => l.line === "never"));
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});
