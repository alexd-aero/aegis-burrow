// Burrow's addon host reads the same forge-addon.json as Selkies Forge, with
// the same rules. These cases mirror the forge's tests (tests/test_addons.py).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.HOME = mkdtempSync(join(tmpdir(), "burrow-test-home-"));     // the scan looks here, nowhere real
const A = await import("../burrow/addons.mjs");

function addon(root, manifest = {}, files = {}) {
  mkdirSync(root, { recursive: true });
  const m = { spec: 1, id: "demo", name: "Demo", version: "1.2.3", scripts: { install: "install.sh", status: "status.sh" }, ...manifest };
  writeFileSync(join(root, "forge-addon.json"), JSON.stringify(m));
  const base = { "install.sh": "echo ::progress 50 half way\necho hello\necho ::open http://127.0.0.1:1/\n",
                 "status.sh": 'echo \'{"state":"running","url":"http://127.0.0.1:1/x","port":9}\'\n', ...files };
  for (const [n, body] of Object.entries(base)) { mkdirSync(join(root, n, ".."), { recursive: true }); writeFileSync(join(root, n), body); }
  return root;
}
const tmp = () => mkdtempSync(join(tmpdir(), "burrow-test-"));

test("sources", () => {
  let s = A.parseSource("https://github.com/o/r/tree/main/addons/hello-forge");
  assert.deepEqual([s.url, s.ref, s.subdir], ["https://github.com/o/r", "main", "addons/hello-forge"]);
  s = A.parseSource("https://example.com/r.git#pkg/addon");
  assert.equal(s.subdir, "pkg/addon");
  assert.throws(() => A.parseSource("https://github.com/o/r#../x"), A.AddonError);
  assert.throws(() => A.parseSource("not a link"), A.AddonError);
});

test("sources: a download link is not a repository", () => {
  // named like an archive, wherever the name sits in the link
  for (const u of ["https://cdn.example.com/files/addon.tar.gz",
                   "https://cdn.example.com/files/addon.tgz?token=abc",
                   "https://cdn.example.com/d/9f?file=addon.zip",
                   "https://cdn.example.com/download/addon.tar.gz/",
                   "https://cdn.example.com/x/addon.tar"]) {
    assert.equal(A.parseSource(u).kind, "archive", u);
  }
  // plainly a repository: cloned on sight
  for (const u of ["https://github.com/o/r", "https://gitlab.com/o/r", "https://codeberg.org/o/r",
                   "https://git.example.com/o/r", "https://example.com/o/r.git", "git@github.com:o/r.git"]) {
    assert.equal(A.parseSource(u).kind, "git", u);
  }
  // neither: looked at before it is judged, instead of failing as a bad repo
  for (const u of ["https://cdn.example.com/download", "https://files.example.com/addons/hello/latest",
                   "https://example.com/d/abc123"]) {
    assert.equal(A.parseSource(u).kind, "web", u);
  }
  // a tree link still wins over the host guess
  const t = A.parseSource("https://codeberg.org/o/r/src/branch/main/addons/x");
  assert.equal(t.kind, "git");
  assert.equal(t.ref, "main");
});

test("the manifest: same rules as the forge", () => {
  const d = addon(tmp());
  const m = A.loadManifest(d);
  assert.deepEqual(m.platforms, ["selkies-forge", "burrow"]);
  for (const bad of [{ id: "X" }, { spec: 2 }, { scripts: { install: "../x.sh" } }, { scripts: { install: "install.sh", instal: "x" } },
                     { platforms: ["windows"] }, { platforms: [] }, { requires: { burrow: "two" } },
                     { actions: [{ id: "install", label: "x", script: "install.sh" }] }, { integration: { dir: "/etc" } }]) {
    addon(d, bad);
    assert.throws(() => A.loadManifest(d), A.AddonError, JSON.stringify(bad));
  }
  addon(d, { platforms: ["selkies-forge"] });
  assert.match(A.checkRequirements(A.loadManifest(d), "2.0.0")[0], /made for Selkies Forge, not Burrow/);
  addon(d, { requires: { burrow: ">=9.0.0" } });
  assert.match(A.checkRequirements(A.loadManifest(d), "2.0.0")[0], /needs Burrow 9\.0\.0/);
  rmSync(d, { recursive: true });
});

test("update_card: the addon dresses its update card; bad keys are named", () => {
  const d = addon(tmp());
  assert.equal(A.loadManifest(d).update_card, null, "none: the host's own card");
  addon(d, { update_card: { theme: "red", urgency: "security", badge: "SECURITY", icon: "shield", title: "{name} {version}: a security fix",
                            tagline: "Closes a hole in the payload check.", highlights: ["Blocks a new phishing kit", "Faster lists"], button: "Update now", notes: "https://example.com/notes", style: "solid", accent: "#FF5A52" } });
  const c = A.loadManifest(d).update_card;
  assert.equal(c.theme, "red"); assert.equal(c.accent, "#ff5a52"); assert.deepEqual(c.highlights, ["Blocks a new phishing kit", "Faster lists"]);
  for (const bad of [{ theme: "rainbow" }, { accent: "red" }, { style: "neon" }, { urgency: "meh" }, { icon: "cat" }, { badge: "A VERY LONG BADGE TEXT" },
                     { highlights: ["1", "2", "3", "4", "5", "6"] }, { highlights: ["x".repeat(101)] }, { notes: "ftp://x" }, { colour: "red" }, "red"]) {
    addon(d, { update_card: bad });
    assert.throws(() => A.loadManifest(d), A.AddonError, JSON.stringify(bad));
  }
  assert.equal(A.cleanUpdateCard({}), null, "an empty card is no card");
  rmSync(d, { recursive: true });
});

test("add, install, status, action, uninstall, remove (a local folder, no network)", async () => {
  const dir = tmp();
  const src = addon(tmp(), { id: "life", settings: [{ key: "WORD", label: "Word", default: "hi" }],
                             actions: [{ id: "poke", label: "Poke", script: "poke.sh" }],
                             scripts: { install: "install.sh", status: "status.sh", uninstall: "uninstall.sh" } },
                    { "install.sh": 'echo "word=$ADDON_SETTING_WORD forge=$FORGE_ADDON_SETTING_WORD host=$ADDON_HOST adopt=$ADDON_ADOPT"\necho ::open http://127.0.0.1:9/\n',
                      "uninstall.sh": 'echo "keep=$ADDON_KEEP_DATA"\n', "poke.sh": "echo poked\n" });
  const H = new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
  const wait = async (j) => { for (let i = 0; i < 100 && H.job(j.id).state === "running"; i++) await new Promise((r) => setTimeout(r, 50)); return H.job(j.id); };
  const a = await H.add(src);
  assert.equal(a.installed, false);
  let job = await wait(H.install("life", { WORD: "yo" }));
  assert.equal(job.state, "done", job.error);
  assert.ok(job.lines.some((l) => l.line === "word=yo forge=yo host=burrow adopt=0"));
  assert.equal(job.result.open_url, "http://127.0.0.1:9/");
  const [v] = await H.list();
  assert.equal(v.status.state, "running");
  assert.equal(v.status.port, 9);
  job = await wait(H.action("life", "poke"));
  assert.ok(job.lines.some((l) => l.line === "poked"));
  job = await wait(H.uninstall("life", false));
  assert.ok(job.lines.some((l) => l.line === "keep=0"));
  assert.equal(H.remove("life").ok, true);
  rmSync(dir, { recursive: true }); rmSync(src, { recursive: true });
});

test("the smart scan finds addons on this machine", async () => {
  const code = join(process.env.HOME, "code");
  addon(join(code, "gizmo"), { id: "gizmo", scripts: { install: "install.sh", detect: "detect.sh", status: "status.sh" } },
        { "detect.sh": 'echo \'{"version":"0.9"}\'\n', "status.sh": 'echo \'{"state":"stopped"}\'\n' });
  addon(join(code, "forgeonly"), { id: "forgeonly", platforms: ["selkies-forge"], replaces: ["oldthing"] });
  addon(join(code, "oldthing"), { id: "oldthing" });                         // replaced: hidden
  addon(join(code, "aegis-burrow"), { id: "aegis-burrow" });                 // ourselves: never listed
  mkdirSync(join(code, "broken")); writeFileSync(join(code, "broken", "forge-addon.json"), "{nope");
  const dir = tmp();
  const H = new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
  const r = await H.scan(0);
  const by = Object.fromEntries(r.addons.map((e) => [e.id, e]));
  assert.deepEqual([by.gizmo.found, by.gizmo.state, by.gizmo.installed_version, by.gizmo.compatible], [true, "stopped", "0.9", true]);
  assert.equal(by.forgeonly.compatible, false);
  assert.equal(by["aegis-burrow"], undefined);
  assert.equal(r.broken.length, 1);
  assert.equal(by.oldthing, undefined);
  rmSync(dir, { recursive: true });
});

test("sources: GitLab (subgroups, self-hosted), blob links, archives", () => {
  let s = A.parseSource("https://gitlab.com/grp/sub/repo/-/tree/main/addons/x");
  assert.deepEqual([s.kind, s.url, s.ref, s.subdir], ["git", "https://gitlab.com/grp/sub/repo", "main", "addons/x"]);
  s = A.parseSource("https://git.example.org/g/r/-/blob/dev/forge-addon.json");
  assert.deepEqual([s.url, s.ref, s.subdir], ["https://git.example.org/g/r", "dev", ""]);
  s = A.parseSource("https://github.com/o/r/archive/refs/heads/main.zip#addons/x");
  assert.deepEqual([s.kind, s.format, s.subdir], ["archive", "zip", "addons/x"]);
  assert.equal(A.parseSource("https://x.org/r.tgz?t=1").format, "tar");
});

test("archives: inspected statically, added, checked; unsafe ones refused", async () => {
  const { execFileSync } = await import("node:child_process");
  const { createServer } = await import("node:http");
  const { readFileSync } = await import("node:fs");
  const www = tmp(), src = join(tmp(), "zippy-main");
  addon(src, { id: "zippy", name: "Zippy" });
  execFileSync("python3", ["-c", `
import zipfile, os, sys
src, www = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(os.path.join(www, "zippy.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    for n in os.listdir(src): z.write(os.path.join(src, n), "zippy-main/" + n)
with zipfile.ZipFile(os.path.join(www, "evil.zip"), "w") as z:
    z.writestr("../../escape.sh", "echo gotcha")`, src, www]);
  execFileSync("tar", ["-czf", join(www, "zippy.tar.gz"), "-C", join(src, ".."), "zippy-main"]);
  const srv = createServer((q, r) => { try { r.end(readFileSync(join(www, q.url.slice(1)))); } catch { r.statusCode = 404; r.end(); } });
  await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${srv.address().port}/`;
  const dir = tmp();
  const H = new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
  try {
    for (const n of ["zippy.zip", "zippy.tar.gz"]) {
      const r = await H.inspect(base + n);
      assert.deepEqual([r.valid, r.manifest.id, r.registered], [true, "zippy", false]);
      assert.match(r.commit, /^sha256:[0-9a-f]{64}$/);
    }
    assert.deepEqual(Object.keys(H.load()), []);                 // inspect adds nothing
    const a = await H.add(base + "zippy.zip");
    assert.equal(a.id, "zippy");
    assert.equal((await H.checkUpdates("zippy")).up_to_date, true);
    await assert.rejects(H.inspect(base + "evil.zip"), /unsafe path/);
  } finally { srv.close(); rmSync(dir, { recursive: true }); rmSync(www, { recursive: true }); }
});

test("updates: checked in the background, listed for the Burrow page", async () => {
  const { execFileSync } = await import("node:child_process");
  const { createServer } = await import("node:http");
  const { readFileSync } = await import("node:fs");
  const www = tmp(), src = join(tmp(), "pagey-main");
  const pack = (version) => {
    addon(src, { id: "pagey", name: "Pagey", version });
    execFileSync("tar", ["-czf", join(www, "pagey.tar.gz"), "-C", join(src, ".."), "pagey-main"]);
  };
  pack("1.0.0");
  const srv = createServer((q, r) => { try { r.end(readFileSync(join(www, q.url.slice(1)))); } catch { r.statusCode = 404; r.end(); } });
  await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
  const dir = tmp();
  const H = new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
  try {
    await H.add(`http://127.0.0.1:${srv.address().port}/pagey.tar.gz`);
    await H.checkAll(0);
    assert.deepEqual(H.updates(), []);                             // not installed: nothing to offer
    const job = H.install("pagey", {});
    while (H.job(job.id).state === "running") await new Promise((ok) => setTimeout(ok, 50));
    await H.checkAll(0);
    assert.deepEqual(H.updates(), []);                             // the same archive
    pack("1.1.0");
    await H.checkAll(3600e3);
    assert.deepEqual(H.updates(), []);                             // checked a moment ago: not again
    await H.checkAll(0);
    const [u] = H.updates();
    assert.deepEqual([u.id, u.name, u.version, u.latest], ["pagey", "Pagey", "1.0.0", "1.1.0"]);
    const up = H.update("pagey");
    while (H.job(up.id).state === "running") await new Promise((ok) => setTimeout(ok, 50));
    assert.equal(H.job(up.id).state, "done");
    assert.deepEqual(H.updates(), []);                             // updated: the card goes away
  } finally { srv.close(); rmSync(dir, { recursive: true }); rmSync(www, { recursive: true }); }
});

// The watchdog: an addon that stops on its own is noticed, and started again
// only once the user says so (or said "always").
test("watchdog: stopped on its own vs stopped by Burrow", async () => {
  const dir = tmp();
  const flag = join(dir, "state");
  writeFileSync(flag, "running");
  const src = addon(tmp(), { id: "dog", actions: [{ id: "start", label: "Start", script: "start.sh" }, { id: "stop", label: "Stop", script: "stop.sh" }] },
                    { "status.sh": `echo "{\\"state\\":\\"$(cat '${flag}')\\"}"\n`,
                      "start.sh": `printf running > '${flag}'\n`, "stop.sh": `printf stopped > '${flag}'\n` });
  const H = new A.Addons({ dir: join(dir, "addons"), registry: join(dir, "addons.json"), version: "2.0.0", log: () => {} });
  const wait = async (j) => { for (let i = 0; i < 100 && H.job(j.id).state === "running"; i++) await new Promise((r) => setTimeout(r, 50)); return H.job(j.id); };
  await H.add(src);
  await wait(H.install("dog"));
  H.expectUntil.clear();                         // the install was long ago
  await H.watchOnce();
  assert.equal(H.get("dog").watch.state, "running");
  assert.deepEqual(H.downList(), []);

  writeFileSync(flag, "stopped");                // it dies by itself
  await H.watchOnce();
  const [d] = H.downList();
  assert.equal(d.id, "dog");
  assert.equal(d.down.state, "stopped");
  assert.equal(d.down.auto, false, "asks first");
  await H.watchOnce();
  assert.equal(H.downList().length, 1, "asks once, and keeps asking until answered");

  await wait(H.answerDown("dog", { start: true, always: false }));
  await H.watchOnce();
  assert.deepEqual(H.downList(), [], "running again: the question goes");

  await wait(H.action("dog", "stop"));           // stopped from Burrow: no question
  await H.watchOnce();
  assert.deepEqual(H.downList(), []);
  await wait(H.action("dog", "start"));
  H.expectUntil.clear();
  await H.watchOnce();

  H.answerDown("dog", { start: false, always: true });   // "always" from now on
  writeFileSync(flag, "stopped");
  await H.watchOnce();
  for (let i = 0; i < 100 && [...H.jobs.values()].some((j) => j.state === "running"); i++) await new Promise((r) => setTimeout(r, 50));
  assert.equal((await H.status(H.get("dog"), 0)).state, "running", "started again without asking");
  assert.equal(H.downList()[0].down.auto, true);
  await H.watchOnce();
  assert.deepEqual(H.downList(), []);

  H.answerDown("dog", { start: false });
  writeFileSync(flag, "stopped");
  H.setAutoRestart("dog", false);
  await H.watchOnce();
  H.answerDown("dog", { start: false });         // "leave it off"
  assert.deepEqual(H.downList(), []);
  await H.watchOnce();
  assert.deepEqual(H.downList(), [], "left off stays off without asking again");
  rmSync(dir, { recursive: true });
});
