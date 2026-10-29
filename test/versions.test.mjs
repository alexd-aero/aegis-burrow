// Going back: the gate keeps its versions before (aegis/updater.mjs), and an
// addon keeps its checkouts before each update and can roll back to one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, cpSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "aegis-ver-home-"));
const HOME = process.env.AEGIS_HOME = mkdtempSync(join(tmpdir(), "aegis-ver-"));
process.env.AEGIS_CONFIG_DIR = join(HOME, "config");
const A = await import("../burrow/addons.mjs");
const U = await import("../aegis/updater.mjs");
const { VERSION } = await import("../aegis/config.mjs");
const tmp = () => mkdtempSync(join(tmpdir(), "aegis-ver-t-"));

function addon(root, version, log) {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "forge-addon.json"), JSON.stringify({ spec: 1, id: "vee", name: "Vee", version, scripts: { install: "install.sh", status: "status.sh" } }));
  writeFileSync(join(root, "install.sh"), `echo "${version} rollback=\${ADDON_ROLLBACK:-0}" >> '${log}'\n`);
  writeFileSync(join(root, "status.sh"), `echo '{"state":"running"}'\n`);
}

test("an addon rolls back to the version before its update, and can come forward again", async () => {
  const dir = tmp(), src = tmp(), log = join(dir, "ran.log");
  addon(src, "1.0.0", log);
  const H = new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
  const wait = async (j) => { for (let i = 0; i < 200 && H.job(j.id).state === "running"; i++) await new Promise((r) => setTimeout(r, 50)); return H.job(j.id); };
  await H.add(src);
  assert.equal((await wait(H.install("vee"))).state, "done");
  assert.deepEqual(H.keptVersions("vee"), [], "nothing kept before the first update");
  assert.throws(() => H.rollback("vee"), /no earlier version/);

  addon(src, "2.0.0", log);
  assert.equal((await wait(H.update("vee"))).state, "done");
  assert.equal(H.get("vee").installed_version, "2.0.0");
  assert.deepEqual(H.keptVersions("vee").map((k) => k.version), ["1.0.0"]);

  const rb = await wait(H.rollback("vee"));
  assert.equal(rb.state, "done", rb.error);
  const rec = H.get("vee");
  assert.equal(rec.installed_version, "1.0.0");
  assert.equal(rec.manifest.version, "1.0.0");
  assert.equal(rec.hold.version, "2.0.0");
  assert.match(readFileSync(log, "utf8"), /1\.0\.0 rollback=1/, "its script ran again, told it's a rollback");
  assert.deepEqual(H.keptVersions("vee").map((k) => k.version), ["2.0.0"], "the version left is kept, to come back to");
  assert.equal(H.versionsView("vee").current, "1.0.0");

  const fw = await wait(H.rollback("vee", "2.0.0"));
  assert.equal(fw.state, "done", fw.error);
  assert.equal(H.get("vee").installed_version, "2.0.0");
  rmSync(dir, { recursive: true, force: true }); rmSync(src, { recursive: true, force: true });
});

test("the gate keeps its versions, holds the one it leaves, and checks downloads", async () => {
  const store = {};
  const settings = { get: (k) => store[k], set: (p) => Object.assign(store, p) };
  const u = new U.Updater({ settings, log: () => {} });
  clearTimeout(u.timer);
  // a kept version, as an update leaves it
  const old = join(HOME, "versions", "1.0.0");
  mkdirSync(join(old, "aegis"), { recursive: true });
  writeFileSync(join(old, "package.json"), JSON.stringify({ name: "aegis-burrow", version: "1.0.0" }));
  writeFileSync(join(old, "aegis", "server.mjs"), "");
  mkdirSync(join(HOME, "versions", "1.1.0-broken", "aegis"), { recursive: true });
  writeFileSync(join(HOME, "versions", "1.1.0-broken", "package.json"), JSON.stringify({ version: "1.1.0" }));
  const kept = u.kept();
  assert.deepEqual(kept.map((k) => [k.version, k.broken, k.whole]).sort(), [["1.0.0", false, true], ["1.1.0", true, false]]);

  // held back: auto-update skips it and anything older, not something newer
  u.setHold("3.0.0");
  assert.equal(u.held("3.0.0"), true);
  assert.equal(u.held("2.9.9"), true);
  assert.equal(u.held("3.0.1"), false);
  u.setHold(null);
  assert.equal(u.hold, null);

  // the boot record: a version on trial; one the launcher went back from is held
  U.writeBoot({ state: "rolled-back", from: "9.9.9", to: VERSION, failed: "9.9.9", why: "didn't load", at: Date.now() });
  let rang = null; u.onRolledBack = (b) => { rang = b; };
  u.confirmBoot();
  assert.equal(rang.failed, "9.9.9");
  assert.equal(u.hold.version, "9.9.9");
  assert.ok(U.readBoot().noted);

  // a mangled download is refused before anything changes
  const dl = tmp();
  mkdirSync(join(dl, "aegis"), { recursive: true });
  writeFileSync(join(dl, "aegis", "a.mjs"), "export const ok = 1;\n");
  assert.equal(U.syntaxCheck(dl, { same: null }), 1);
  writeFileSync(join(dl, "aegis", "b.mjs"), "export const = cut sho");
  assert.throws(() => U.syntaxCheck(dl, { same: null }), /b\.mjs in the download doesn't parse/);
  // a file the same as the running app's needs no check (it runs already); a changed one does
  const run = tmp(); mkdirSync(join(run, "aegis"), { recursive: true });
  writeFileSync(join(run, "aegis", "a.mjs"), "export const ok = 1;\n");
  rmSync(join(dl, "aegis", "b.mjs"));
  assert.equal(U.syntaxCheck(dl, { same: run }), 0, "unchanged: nothing to check");
  writeFileSync(join(dl, "aegis", "a.mjs"), "export const ok = 2;\n");
  assert.equal(U.syntaxCheck(dl, { same: run }), 1);

  await assert.rejects(Promise.resolve(u.rollback(VERSION)).then((j) => { if (j.state === "error") throw new Error(j.error); }), /is the one running/);
});
