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
