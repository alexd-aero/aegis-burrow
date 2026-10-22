// "Start it": every way an addon can be started, in order, and a report that
// says what happened - whether it worked or not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "rescue-test-home-"));     // nothing real is looked at
process.env.AEGIS_RESCUE_SETTLE_MS = "20";
const A = await import("../burrow/addons.mjs");
const R = await import("../burrow/rescue.mjs");
const tmp = () => mkdtempSync(join(tmpdir(), "rescue-test-"));

function addon(root, id, files) {
  mkdirSync(join(root, "forge"), { recursive: true });
  writeFileSync(join(root, "forge-addon.json"), JSON.stringify({ spec: 1, id, name: id, version: "1.0.0", platforms: ["burrow"],
    scripts: { install: "forge/install.sh", status: "forge/status.sh" }, actions: [{ id: "start", label: "Start", script: "forge/start.sh" }] }));
  for (const [n, body] of Object.entries(files)) writeFileSync(join(root, n), body);
  return root;
}
const host = (dir) => new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
const wait = async (H, j) => { for (let i = 0; i < 400 && H.job(j.id).state === "running"; i++) await new Promise((r) => setTimeout(r, 50)); return H.job(j.id); };

test("the rescue script parses", () => {
  const f = join(tmp(), "r.sh");
  writeFileSync(f, R.RESCUE_SH);
  const { spawnSync } = process.getBuiltinModule("node:child_process");
  assert.equal(spawnSync("bash", ["-n", f]).status, 0);
  assert.ok(!R.RESCUE_SH.includes("\\${"), "no escaped template braces are left in the script");
});

test("a stopped addon whose own start works: started, and the report says how", async () => {
  const dir = tmp();
  const flag = join(dir, "up");
  const src = addon(tmp(), "comes-back", {
    "forge/install.sh": "echo installed\n",
    "forge/status.sh": `[ -f ${flag} ] && echo '{"state":"running"}' || echo '{"state":"stopped","detail":"not running"}'\n`,
    "forge/start.sh": `touch ${flag}; echo started\n` });
  const H = host(dir);
  await H.add(src);
  assert.equal((await wait(H, H.install("comes-back"))).state, "done");
  const job = await wait(H, H.rescue("comes-back"));
  assert.equal(job.state, "done", job.error);
  assert.equal(job.result.ok, true);
  assert.match(job.result.worked, /Start/);
  const text = H.report("comes-back", job.result.file);
  assert.match(text, /is running again/);
  assert.match(text, /## Attempt 1: its own "Start" action/);
  assert.ok(!/## Diagnostics/.test(text), "nothing to diagnose once it runs");
  assert.equal(H.reports("comes-back").length, 1);
});

test("an addon that will not start: every way is tried, the logs are collected, nothing is left half-done", async () => {
  const dir = tmp();
  const src = addon(tmp(), "stays-down", {
    "forge/install.sh": 'mkdir -p "$ADDON_DATA"; echo "listen EADDRINUSE 4888" >> "$ADDON_DATA/app.log"; echo repaired\n',
    "forge/status.sh": `echo '{"state":"error","detail":"port 4888 is taken"}'\n`,
    "forge/start.sh": "echo 'Error: listen EADDRINUSE' >&2; exit 1\n" });
  const H = host(dir);
  await H.add(src);
  await wait(H, H.install("stays-down"));
  const job = await wait(H, H.rescue("stays-down"));
  assert.equal(job.state, "done", job.error);
  assert.equal(job.result.ok, false);
  const text = H.report("stays-down", job.result.file);
  assert.match(text, /would not start/);
  assert.match(text, /Status before\nerror\nport 4888 is taken/);
  assert.match(text, /Error: listen EADDRINUSE/, "what the start printed");
  assert.match(text, /as a repair/, "the install ran again as the last try");
  assert.match(text, /## Diagnostics/);
  assert.match(text, /listen EADDRINUSE 4888/, "its own log file is in the report");
  assert.ok(!existsSync(join(dir, "addons", "stays-down", "rescue", "rescue.sh")), "the script is cleaned up");
  assert.throws(() => H.report("stays-down", "../../addons.json"), /No such report/, "only its own reports are served");
});

test("a report is kept, at most five of them", async () => {
  const dir = tmp();
  const src = addon(tmp(), "five", { "forge/install.sh": "true\n", "forge/status.sh": `echo '{"state":"running"}'\n`, "forge/start.sh": "true\n" });
  const H = host(dir);
  await H.add(src);
  await wait(H, H.install("five"));
  for (let i = 0; i < 7; i++) { await wait(H, H.rescue("five")); await new Promise((r) => setTimeout(r, 1100)); }
  assert.equal(H.reports("five").length, 5);
});
