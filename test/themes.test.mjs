// Weft themes (aegis/themes.mjs) and your own backgrounds (aegis/backdrops.mjs):
// the manifest, archives inside archives, staging, confirm, the safety scan,
// .stability (made, checked, tampered with), Discover, and links to pictures.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";
import * as T from "../aegis/themes.mjs";
import { Backdrops, fetchLink, sniff, isPublic } from "../aegis/backdrops.mjs";

const tmp = (p = "aegis-th-") => mkdtempSync(join(tmpdir(), p));
const PNG = Buffer.from("89504e470d0a1a0a0000000d4948445200000001000000010806000000" + "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082", "hex");
// a zip with the files stored as they are (enough for the reader)
function zip(files) {
  const parts = [], central = [];
  let off = 0;
  for (const [name, data0] of Object.entries(files)) {
    const data = Buffer.isBuffer(data0) ? data0 : Buffer.from(data0);
    const n = Buffer.from(name), c = crc32(data);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(c, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(n.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(c, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    parts.push(lh, n, data); central.push(ch, n);
    off += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}
const manifest = (o = {}) => JSON.stringify({ weft: 1, kind: "theme", api: 1, id: "night", name: "Night", version: "1.0.0", description: "A dark look.", author: "tester",
  root: "theme", previews: [{ file: "previews/home.png", caption: "Home" }], accent: "#7aa7ff",
  backgrounds: { builtin: [{ id: "deep", name: "Deep", swatch: "linear-gradient(#000, #123)" }], recommended: [{ name: "Corridor", url: "https://www.wallpaperflare.com/x-wallpaper-ab1", tags: ["Liminal"], preview: "previews/home.png" }] },
  onboarding: [{ title: "Hello", body: "It's dark now.", button: { label: "Burrow", href: "/__gate/tunnels" } }], ...o });
const files = (extra = {}, m = {}) => ({ ".theme": manifest(m), "previews/home.png": PNG, "theme/ui.css": "body { background: #000; }\n",
  "theme/home.js": 'import { api } from "./common.js";\nexport const x = 1;\nfetch("/__gate/api/termix");\n', "theme/assets/bg.png": PNG, "theme/login.js": "steal()", ...extra });
const folder = (fs) => { const d = tmp(); for (const [n, v] of Object.entries(fs)) { mkdirSync(join(d, n, ".."), { recursive: true }); writeFileSync(join(d, n), v); } return d; };
const host = (dir = tmp()) => new T.Themes({ dir, version: "2.45.0", log: () => {} });
const LIVE = [{ page: "home", errors: 0, ok: true, ms: 300 }, { page: "tunnels", errors: 0, ok: true, ms: 400 }, { page: "settings", errors: 0, ok: true, ms: 500 }];

test("the manifest: required fields, previews, api, paths", () => {
  assert.ok(T.readManifest(manifest()).m);
  const errs = (o) => T.readManifest(manifest(o)).errors.join(" | ");
  assert.match(errs({ previews: [] }), /needs a preview/);
  assert.match(errs({ api: 2 }), /theme API 2.*Update Aegis/);
  assert.match(errs({ kind: "addon" }), /"kind" must be "theme"/);
  assert.match(errs({ id: "No Caps" }), /"id"/);
  assert.match(errs({ version: "v1" }), /"version"/);
  assert.match(errs({ previews: ["../x.png"] }), /inside the package/);
  assert.match(errs({ previews: ["previews/x.svg"] }), /must be a \.png/);
  assert.match(T.readManifest("{nope").errors[0], /not valid JSON/);
  const m = T.readManifest(manifest({ backgrounds: { builtin: [{ id: "aa", name: "A", swatch: "url(https://evil/x.png)" }], recommended: [{ name: "x", url: "javascript:alert(1)" }] } })).m;
  assert.equal(m.backgrounds.builtin[0].swatch, "#111", "no url() in a swatch");
  assert.equal(m.backgrounds.recommended.length, 0, "only http(s) links are recommended");
  const ob = T.readManifest(manifest({ onboarding: [{ title: "t", button: { label: "x", href: "javascript:alert(1)" } }, { body: "no title" }] }));
  assert.equal(ob.m.onboarding.length, 1); assert.equal(ob.m.onboarding[0].button, null); assert.ok(ob.warnings.length);
  assert.equal(T.satisfies("2.45.1", ">=2.45.0 <3"), true); assert.equal(T.satisfies("3.0.0", ">=2.45.0 <3"), false); assert.equal(T.satisfies("2.44.9", ">=2.45.0"), false);
});

test("archives inside archives: the .theme is found however deep (up to 3)", () => {
  const d = tmp(), inner = zip(Object.fromEntries(Object.entries(files()).map(([k, v]) => [`night-theme/${k}`, v])));
  writeFileSync(join(d, "outer.zip"), zip({ "readme.txt": "hi", "bundle/theme.zip": zip({ "again.zip": inner }) }));
  const found = T.findThemes(d);
  assert.equal(found.length, 1);
  assert.ok(existsSync(join(found[0], ".theme")));
  const deep = tmp();
  let z = inner; for (let i = 0; i < 5; i++) z = zip({ [`l${i}.zip`]: z });
  writeFileSync(join(deep, "x.zip"), z);
  assert.equal(T.findThemes(deep).length, 0, "too deep: refused");
});

test("inspect → report → confirm → apply; served only for what a theme may replace", async () => {
  const H = host();
  const r = await H.inspect({ buffer: zip(Object.fromEntries(Object.entries(files()).map(([k, v]) => [`wrap/${k}`, v]))), filename: "night.zip" });
  assert.equal(r.ok, true, r.errors.join(", "));
  assert.deepEqual(r.files.replaces.sort(), ["home.js", "ui.css"]);
  assert.ok(r.files.ignored.some((f) => f.path === "login.js" && /sign-in/.test(f.why)), "login.js is never served");
  assert.equal(r.stability.level, "unproven");
  assert.equal(r.manifest.previews[0].url, `/__gate/api/themes/staged/${r.token}/file/previews/home.png`);
  assert.equal(r.preview, `/__gate/theme-preview/${r.token}/`);
  assert.ok(H.file("ui.css", { token: r.token }), "the preview serves it before it's applied");
  assert.equal(H.file("ui.css"), null, "nothing changes before apply");
  assert.throws(() => H.apply(r.token), /Confirm first/);
  const v = H.apply(r.token, { confirm: true });
  assert.equal(v.active, "night");
  assert.match(H.file("ui.css").buf.toString(), /#000/);
  assert.equal(H.file("login.js"), null);
  assert.equal(H.file("settings.js"), null, "what it doesn't replace stays ours");
  assert.ok(H.file("assets/bg.png"));
  assert.equal(H.file("ui.css", { off: true }), null, "the default look, for a browser that asked");
  const info = H.activeInfo();
  assert.equal(info.welcome, true, "the welcome shows once");
  assert.equal(info.background, "theme:deep");
  assert.equal(info.backgrounds.recommended[0].preview, "/__gate/theme-file/night/previews/home.png");
  H.onboarded("night");
  assert.equal(H.activeInfo().welcome, false);
  // a fresh host reads the same state back
  const H2 = new T.Themes({ dir: H.dir, version: "2.45.0" });
  assert.equal(H2.active.id, "night");
});

test("the safety scan: styles only, what replaced pages handle, and code a theme shouldn't have", async () => {
  const H = host();
  let r = await H.inspect({ buffer: zip({ ".theme": manifest({ root: "" }), "previews/home.png": PNG, "ui.css": "a{color:red}" }) });
  assert.equal(r.safety.level, "styles");
  r = await H.inspect({ buffer: zip(files({ "theme/settings.js": 'export const p = () => fetch("/__gate/api/password");' })) });
  assert.equal(r.safety.level, "review");
  assert.ok(r.safety.findings.some((f) => /Settings page/.test(f.what)));
  assert.ok(r.safety.findings.some((f) => /changes your password, as the page it replaces does/i.test(f.what)));
  r = await H.inspect({ buffer: zip(files({ "theme/home.js": 'export const a = eval("1+1"); fetch("/__gate/api/password");' })) });
  assert.equal(r.safety.level, "danger");
  assert.ok(r.safety.findings.some((f) => f.level === "danger" && /made from text/.test(f.what)));
  assert.ok(r.safety.findings.some((f) => f.level === "warn" && /doesn't need to/.test(f.what)), "home.js has no business with passwords");
  assert.throws(() => H.apply(r.token, { confirm: true }), (e) => e.extra.needsTrust);
  assert.equal(H.apply(r.token, { confirm: true, trust: true }).active, "night");
  r = await H.inspect({ buffer: zip(files({ "theme/home.js": "export const x = ;" })) });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(" "), /home\.js doesn't parse/);
});

test(".stability: made from a live run, checked file by file, and caught when anything changes", async () => {
  const H = host();
  const r = await H.inspect({ buffer: zip(files()) });
  H.apply(r.token, { confirm: true });
  assert.throws(() => H.stamp("night", LIVE.slice(0, 1)), /Run every page first/);
  assert.throws(() => H.stamp("night", LIVE.map((x) => x.page === "tunnels" ? { ...x, errors: 2 } : x)), /Not stable yet: errors/);
  const { text } = H.stamp("night", LIVE);
  assert.match(text, /^weft-stability 1\ntheme night 1\.0\.0\napi 1\nhost burrow 2\.45\.0\n/);
  assert.match(text, /\ncheck pages ok home drew, tunnels drew, settings drew\n/);
  assert.match(text, /\nfile [0-9a-f]{64} \d+ theme\/ui\.css\n/);
  assert.match(text, /\nseal [0-9a-f]{64}\n$/);
  const p = H.readPackage("night");
  const v = () => T.verifyStability(p.pkg, p.m, T.listFiles(p.pkg), { version: "2.45.3" });
  assert.equal(v().level, "stable", v().title);
  assert.equal(T.verifyStability(p.pkg, p.m, T.listFiles(p.pkg), { version: "2.47.0" }).level, "aged");
  assert.equal(T.verifyStability(p.pkg, p.m, T.listFiles(p.pkg), { version: "2.44.0" }).level, "newer");
  // one byte in one file
  const css = join(p.pkg, "theme/ui.css"), keep = readFileSync(css);
  appendFileSync(css, " ");
  assert.equal(v().level, "changed"); assert.match(v().lines[0], /theme\/ui\.css is different/);
  writeFileSync(css, keep);
  writeFileSync(join(p.pkg, "theme/extra.css"), "x");
  assert.match(v().lines.join(), /theme\/extra\.css was added/);
  rmSync(join(p.pkg, "theme/extra.css"));
  assert.equal(v().level, "stable");
  // a line edited by hand: the seal says so
  const sp = join(p.pkg, ".stability");
  writeFileSync(sp, readFileSync(sp, "utf8").replace("check errors ok 0 uncaught", "check errors ok 0 uncaught (honest)"));
  assert.equal(v().level, "changed"); assert.match(v().lines[0], /seal/);
  writeFileSync(sp, "hello\n");
  assert.equal(v().level, "broken");
  // and it travels: a re-upload with the file keeps its proof
  writeFileSync(sp, text);
  const again = await H.inspect({ buffer: zip({ ...files(), ".stability": text }) });
  assert.equal(again.stability.level, "stable", again.stability.lines.join("; "));
  assert.equal(again.installed.newer, 0);
});

test("several themes in one upload: you pick one", async () => {
  const H = host();
  const two = { ...Object.fromEntries(Object.entries(files()).map(([k, v]) => [`a/${k}`, v])), ...Object.fromEntries(Object.entries(files({}, { id: "day", name: "Day" })).map(([k, v]) => [`b/${k}`, v])) };
  const r = await H.inspect({ buffer: zip(two) });
  assert.equal(r.choose.length, 2);
  assert.deepEqual(r.choose.map((c) => c.name).sort(), ["Day", "Night"]);
  const day = r.choose.find((c) => c.name === "Day");
  const r2 = await H.inspect(null, { token: r.token, pick: day.i });
  assert.equal(r2.manifest.id, "day");
  assert.equal(r2.ok, true);
});

test("switching, the default look, an older version back, removing", async () => {
  const H = host();
  H.apply((await H.inspect({ buffer: zip(files()) })).token, { confirm: true });
  H.apply((await H.inspect({ buffer: zip(files({ "theme/ui.css": "body{color:blue}" }, { version: "1.1.0" })) })).token, { confirm: true });
  assert.match(H.file("ui.css").buf.toString(), /blue/);
  const v = H.view();
  assert.equal(v.themes[0].version, "1.1.0"); assert.equal(v.themes[0].hasPrevious, true);
  H.rollback("night");
  assert.match(H.file("ui.css").buf.toString(), /#000/);
  assert.equal(H.view().themes[0].version, "1.0.0");
  H.use(null);
  assert.equal(H.file("ui.css"), null);
  H.use("night");
  assert.ok(H.file("ui.css"));
  assert.equal(H.setBackground("theme:deep"), "theme:deep");
  assert.throws(() => H.setBackground("theme:nope"), /No such background/);
  H.setBackground("img:abc123");
  H.dropBackground("abc123");
  assert.equal(H.activeInfo().background, "theme:deep", "a deleted picture: the theme's own again");
  H.remove("night");
  assert.equal(H.view().themes.length, 0); assert.equal(H.file("ui.css"), null);
});

test("Discover: Weft's own examples, then forks with a .theme", async () => {
  const calls = [];
  const fake = async (u) => {
    calls.push(u);
    const j = (o) => ({ ok: true, status: 200, json: async () => o, text: async () => JSON.stringify(o) });
    if (u === "https://api.github.com/repos/alexd-aero/weft") return j({ default_branch: "main", stargazers_count: 7, pushed_at: "2026-11-01T00:00:00Z" });
    if (u.includes("/contents/examples/themes")) return j([{ type: "dir", path: "examples/themes/midnight" }]);
    if (u.includes("/forks?")) return j([{ full_name: "sam/weft", default_branch: "main", stargazers_count: 3, pushed_at: "2026-11-05T00:00:00Z", owner: { login: "sam" } },
                                           { full_name: "lee/weft", default_branch: "dev", stargazers_count: 9, pushed_at: "2026-11-02T00:00:00Z", owner: { login: "lee" } }]);
    if (u === "https://raw.githubusercontent.com/alexd-aero/weft/main/examples/themes/midnight/.theme") return { ok: true, text: async () => manifest({ id: "midnight", name: "Midnight" }) };
    if (u === "https://raw.githubusercontent.com/sam/weft/main/.theme") return { ok: true, text: async () => manifest({ id: "sunny", name: "Sunny" }) };
    return { ok: false, status: 404, text: async () => "" };
  };
  const H = new T.Themes({ dir: tmp(), version: "2.45.0", fetch: fake });
  const d = await H.discover();
  assert.equal(d.error, null);
  assert.deepEqual(d.featured.map((x) => x.name), ["Midnight"]);
  assert.equal(d.featured[0].source, "https://github.com/alexd-aero/weft/tree/main/examples/themes/midnight");
  assert.deepEqual(d.community.map((x) => [x.name, x.author, x.stars]), [["Sunny", "tester", 3]]);
  assert.match(d.community[0].previews[0].url, /^\/__gate\/api\/themes\/discover\/img\?u=https%3A%2F%2Fraw\.githubusercontent\.com%2Fsam%2Fweft%2Fmain%2Fpreviews%2Fhome\.png$/);
  const n = calls.length;
  await H.discover();
  assert.equal(calls.length, n, "an hour's cache");
  await assert.rejects(H.discoverImage("https://evil.example/x.png"), /Not a theme picture/);
  await assert.rejects(H.discoverImage("https://raw.githubusercontent.com/a/b/main/x.svg"), /Not a theme picture/);
});

test("checkFolder: what `aegis themes check` and weft-check say", () => {
  const d = folder(files());
  const r = T.checkFolder(d, { version: "2.45.0" });
  assert.equal(r.ok, true, r.errors.join());
  assert.equal(r.stability.level, "unproven");
  assert.equal(T.checkFolder(tmp()).ok, false);
});

// ------------------------------------------------------------------ backgrounds
test("backgrounds: what the bytes are, public addresses only", () => {
  assert.equal(sniff(PNG).kind, "image");
  assert.equal(sniff(Buffer.from("GIF89a" + "x".repeat(20))).kind, "gif");
  assert.equal(sniff(Buffer.concat([Buffer.from([0, 0, 0, 0x20]), Buffer.from("ftypisom"), Buffer.alloc(8)])).kind, "video");
  assert.equal(sniff(Buffer.from([0x1a, 0x45, 0xdf, 0xa3, ...Array(12).fill(0)])).ext, "webm");
  assert.equal(sniff(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>   ')).kind, "svg");
  assert.equal(sniff(Buffer.from("<!doctype html><html><head></head></html>")).kind, "html");
  for (const a of ["10.1.2.3", "127.0.0.1", "192.168.1.5", "172.20.0.1", "100.66.153.83", "169.254.1.1", "::1", "fd00::1", "fe80::1", "::ffff:192.168.1.1"]) assert.equal(isPublic(a), false, a);
  for (const a of ["1.1.1.1", "104.16.1.1", "2606:4700::1111"]) assert.equal(isPublic(a), true, a);
});

test("backgrounds from links: wallpaperflare pages, direct pictures, GIFs; SVG and pages without one refused", async () => {
  const pages = {
    "https://www.wallpaperflare.com/moon-dunes-wallpaper-abc12/download": { status: 200, buf: Buffer.from('<!doctype html><html><head></head><body><img class="x" src="https://r4.wallpaperflare.com/wallpaper/1/2/3/moon-dunes-wallpaper-ff.jpg" id="show_img"></body></html>') },
    "https://r4.wallpaperflare.com/wallpaper/1/2/3/moon-dunes-wallpaper-ff.jpg": { status: 200, buf: Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(200)]) },
    "https://example.com/spin.gif": { status: 200, buf: Buffer.from("GIF89a" + "x".repeat(50)) },
    "https://example.com/x.svg": { status: 200, buf: Buffer.from("<svg onload=alert(1)></svg>") },
    "https://example.com/page": { status: 200, buf: Buffer.from("<!doctype html><html><head><title>t</title></head></html>") },
    "https://example.com/og": { status: 200, buf: Buffer.from('<!doctype html><html><head><meta property="og:image" content="/pic.png"></head></html>') },
    "https://example.com/pic.png": { status: 200, buf: PNG },
    "https://www.wallpaperflare.com/blocked-wallpaper-zz1/download": { status: 403, buf: Buffer.from("Just a moment...") },
  };
  const seen = [];
  const getter = async (u, o) => { seen.push([u, o.referer]); const p = pages[u]; if (!p) return { status: 404, buf: Buffer.alloc(0), url: u }; return { ...p, url: u, type: "" }; };
  const w = await fetchLink("https://www.wallpaperflare.com/moon-dunes-wallpaper-abc12", { getter });
  assert.equal(w.kind, "image"); assert.equal(w.name, "moon dunes"); assert.equal(w.source, "https://www.wallpaperflare.com/moon-dunes-wallpaper-abc12");
  assert.equal(seen[0][1], "https://www.wallpaperflare.com/moon-dunes-wallpaper-abc12", "asked like the page would");
  assert.equal((await fetchLink("https://example.com/spin.gif", { getter })).kind, "gif");
  assert.equal((await fetchLink("https://example.com/og", { getter })).kind, "image", "a page that names its picture");
  await assert.rejects(fetchLink("https://example.com/x.svg", { getter }), /SVG pictures can carry scripts/);
  await assert.rejects(fetchLink("https://example.com/page", { getter }), /doesn't show a picture/);
  await assert.rejects(fetchLink("https://www.wallpaperflare.com/blocked-wallpaper-zz1", { getter }), /browser check.*upload the file/);
  await assert.rejects(fetchLink("ftp://x/y.png", { getter }), /http\(s\) link/);
});

test("backgrounds kept here: pictures in three sizes, GIFs and videos as they are, a still for each", () => {
  const B = new Backdrops(tmp());
  const jpg = "data:image/jpeg;base64," + Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(200, 1)]).toString("base64");
  const img = B.add({ name: "Twilight", l: jpg, s: jpg, t: jpg, w: 3840, h: 2160, source: "https://www.wallpaperflare.com/x" });
  assert.equal(img.kind, "image"); assert.ok(B.file(`${img.id}-l.jpg`)); assert.equal(B.file(`${img.id}.gif`), null);
  const gif = B.addRaw(Buffer.from("GIF89a" + "x".repeat(200)), { name: "Spin" });
  assert.equal(gif.kind, "gif"); assert.equal(B.file(`${gif.id}.gif`).type, "image/gif");
  const vid = B.addRaw(Buffer.concat([Buffer.from([0, 0, 0, 0x20]), Buffer.from("ftypisom"), Buffer.alloc(300)]), { name: "Rain" });
  assert.equal(vid.ext, "mp4");
  B.poster(vid.id, jpg, { w: 1920, h: 1080 });
  assert.equal(B.list().find((x) => x.id === vid.id).poster, true);
  assert.throws(() => B.addRaw(PNG), /sized by your browser/);
  assert.throws(() => B.addRaw(Buffer.from("<svg></svg>" + " ".repeat(20))), /SVG/);
  assert.equal(B.file("../etc-l.jpg"), null);
  B.rename(gif.id, "Spinner");
  assert.equal(B.list().find((x) => x.id === gif.id).name, "Spinner");
  assert.equal(B.remove(vid.id), true);
  assert.equal(B.file(`${vid.id}.mp4`), null);
  assert.equal(B.list().length, 2);
});

test("theme.css: styles layered on top of ui.css, the easy kind of theme", async () => {
  const H = host();
  const r = await H.inspect({ buffer: zip({ ".theme": manifest({ root: "" }), "previews/home.png": PNG, "theme.css": ":root { --bg: #000814; }" }) });
  assert.equal(r.ok, true, r.errors.join());
  assert.equal(r.files.layered, true);
  assert.equal(r.safety.level, "styles");
  H.apply(r.token, { confirm: true });
  assert.match(H.file("theme.css").buf.toString(), /#000814/);
  assert.equal(H.file("ui.css"), null, "ui.css stays ours");
});
