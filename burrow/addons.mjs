// Burrow, the engine: addons.
//
// The same addons as Selkies Forge, read the same way. An addon is a folder
// (usually a git repository) with a forge-addon.json and a few bash scripts;
// the format is universal: every host reads the same manifest with the same
// rules and runs the same scripts with the same environment. An addon runs on
// every host unless its manifest names the ones it is made for:
//
//   "platforms": ["selkies-forge", "burrow"]     (the default: both)
//
// The rules below mirror Selkies Forge's (animated-fiesta, src/forge/addons.py);
// docs/addons.md there is the full guide.
//
// Scripts get, on every host:
//   ADDON_ID ADDON_NAME ADDON_VERSION ADDON_DIR ADDON_DATA ADDON_SPEC
//   ADDON_SETTING_<KEY>  ADDON_ADOPT  ADDON_UPDATE  ADDON_KEEP_DATA
//   ADDON_HOST (selkies-forge | burrow)  ADDON_HOST_VERSION  ADDON_HOST_URL  ADDON_BIND
// and the same values as FORGE_ADDON_*, for scripts written before ADDON_*.
// Burrow adds BURROW_SOCKET: its control socket, to publish a port.
//
// Root: "requires": {"root": "why"} means install, update and uninstall need
// root; an action with "root": true does too. Such a job only starts once the
// user said yes (and typed their sudo password when sudo asks for one); its
// script then gets ADDON_ROOT=1, ADDON_ASKPASS_TOKEN and SUDO_ASKPASS, and
// calls `sudo -A`. See burrow/root.mjs.
//
// Or in the user's own terminal (`aegis addons install ID`, automatically when
// this Aegis can't get root, e.g. under a sandboxed systemd unit): the job is
// made here as always, but its script step is handed out once, on the control
// socket only, as a run spec (POST /addons/<id>/runspec -> {job, token, script,
// cwd, env}); the CLI runs `bash script` with the terminal as stdin (a plain
// sudo there asks for the password itself), streams the lines back (POST
// /addons/jobs/<job>/line {token, lines}) and the exit code (…/done {token,
// code}), and the job ends exactly as if it had run here. Two hours at most.
//
// Scripts talk back with lines on stdout: "::progress N text", "::phase text",
// "::open URL", "::warn text"; status (and detect) end with one JSON line.

import { spawn, execFile } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, arch as osArch, platform as osPlatform } from "node:os";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { ArchiveError, download, unpack, isArchive } from "./archive.mjs";
import { rescue as rescueAddon, reports as rescueReports, report as rescueReport } from "./rescue.mjs";
import { RootAccess, RootError, terminalHint, terminalCommand } from "./root.mjs";

export const SPEC = 1;
export const MANIFEST = "forge-addon.json";
export const PLATFORMS = ["selkies-forge", "burrow"];
export const HOST = "burrow";
const SELF = ["aegis-burrow", "aegis", "burrow"];
const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const SETTING_RE = /^[A-Z][A-Z0-9_]{0,31}$/;
const ACTION_RE = /^[a-z][a-z0-9-]{0,23}$/;
const SCRIPTS = ["detect", "install", "update", "uninstall", "status"];
const SETTING_TYPES = ["text", "number", "bool", "select", "password"];
const IMAGE_TYPES = { ".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg" };
const MAX_IMAGE = 512 * 1024, MAX_MANIFEST = 64 * 1024;
const WATCH_MISSES = 3;      // the watchdog's checks (a minute apart) that must fail in a row before an addon counts as down
const TIMEOUT = { detect: 20, status: 15, install: 3600, update: 3600, uninstall: 900, action: 900 };
const ARCH_ALIASES = { amd64: "x86_64", x64: "x86_64", arm64: "aarch64", armhf: "armv7l", arm: "armv7l" };
const MASK = "••••••••";

export class AddonError extends Error {}
export const TERMINAL_TTL = 2 * 3600e3;
export { RootError };
// never passed through from Aegis's own environment, and never twinned as FORGE_*
const ROOT_VARS = ["ADDON_ROOT", "ADDON_ASKPASS_TOKEN", "SUDO_ASKPASS", "FORGE_ADDON_ROOT", "FORGE_ADDON_ASKPASS_TOKEN"];
const NO_TWIN = new Set(["ADDON_ROOT", "ADDON_ASKPASS_TOKEN"]);

// systemd-run --user --scope, when this user's systemd manager is there
// (lingering, or logged in); null otherwise. Checked once.
let scopeCache;
function userScope() {
  if (scopeCache !== undefined) return scopeCache;
  scopeCache = null;
  try {
    const uid = process.getuid?.();
    const run = process.env.XDG_RUNTIME_DIR || `/run/user/${uid}`;
    if (uid == null || !existsSync(join(run, "bus"))) return null;
    const bin = (process.env.PATH || "/usr/bin:/bin").split(":").map((d) => join(d, "systemd-run")).find((f) => existsSync(f));
    if (!bin) return null;
    scopeCache = { args: ["--user", "--scope", "--quiet", "--collect"],
                   env: { XDG_RUNTIME_DIR: run, DBUS_SESSION_BUS_ADDRESS: `unix:path=${join(run, "bus")}` } };
  } catch { scopeCache = null; }
  return scopeCache;
}
const fail = (msg) => { throw new AddonError(msg); };

// ------------------------------------------------------------------ sources
// GitHub and Codeberg: OWNER/REPO/tree|blob/REF[/path]
const HOSTED_TREE = /^(https:\/\/(?:github\.com|codeberg\.org)\/[^/\s]+\/[^/\s#]+?)(?:\.git)?\/(?:tree|blob|src\/branch)\/([^/\s#]+)(?:\/([^#\s]*?))?\/?$/;
// GitLab, gitlab.com or self-hosted, with subgroups: GROUP/SUB/.../REPO/-/tree|blob/REF[/path]
const GITLAB_TREE = /^(https:\/\/[^/\s]+\/[^\s#]+?)(?:\.git)?\/-\/(?:tree|blob)\/([^/\s#]+)(?:\/([^#\s]*?))?\/?$/;
// a download: .zip, .tar.gz, .tgz (GitHub's and GitLab's archive links included)
// An archive link: the name can sit anywhere in the path or in a query value
// (a CDN hands out /download/addon.tgz, /d/abc?file=addon.zip, …), not only at
// the very end of the URL.
const ARCHIVE = /^https?:\/\/[^\s#]+\.(zip|tar\.gz|tgz|tar)(?:[/?][^\s#]*)?$/i;
// Plainly a git source: a .git URL, ssh, or one of the hosts that serve repos
// at /owner/name. Anything else over http(s) is looked at before we guess
// (fetchSource): a direct download link is not a repository.
const GIT_PLAIN = /^(?:ssh:\/\/|git@)/;
const GIT_HOST = /^https?:\/\/(?:[^/\s]*\.)?(?:github\.com|gitlab\.com|codeberg\.org|bitbucket\.org|git\.sr\.ht|gitea\.[^/\s]+|git\.[^/\s]+)\/[^/\s]+\/[^/\s]+/i;

export function parseSource(text) {
  const raw = String(text || "").trim();
  if (!raw) fail("Paste a repository link.");
  if (/^(\/|~|\.\/|\.\.\/|file:\/\/)/.test(raw)) {
    const p = resolve(raw.startsWith("file://") ? raw.slice(7) : raw.replace(/^~(?=\/|$)/, homedir()));
    let ok = false;
    try { ok = statSync(p).isDirectory(); } catch { /* missing */ }
    if (!ok) fail(`${p} is not a folder on this machine.`);
    return { kind: "local", path: p, subdir: "", ref: null, display: p };
  }
  let [url, sub = ""] = raw.split("#", 2);
  let ref = null;
  const okSub = (x) => !x || (!x.split("/").includes("..") && /^[A-Za-z0-9._/-]+$/.test(x));
  if (ARCHIVE.test(url)) {
    sub = sub.replace(/^\/+|\/+$/g, "");
    if (!okSub(sub)) fail("The folder part of the link is not valid.");
    return { kind: "archive", url, format: /\.zip(\?|$)/i.test(url) ? "zip" : "tar", ref: null, subdir: sub, display: raw };
  }
  const m = HOSTED_TREE.exec(url) || GITLAB_TREE.exec(url);
  if (m) {
    url = m[1]; ref = m[2]; sub = sub || m[3] || "";
    if (sub === MANIFEST || sub.endsWith("/" + MANIFEST)) sub = sub.slice(0, -MANIFEST.length);   // a /blob/ link to the manifest
  }
  url = url.replace(/\/+$/, "");
  if (!/^(https?:\/\/[^\s/]+\/\S+|ssh:\/\/\S+|git@[^\s:]+:\S+)$/.test(url)) fail("That is not a link Burrow can install from (a git repository, a .zip or .tar.gz, or a direct download link).");
  sub = sub.replace(/^\/+|\/+$/g, "");
  if (sub && (sub.split("/").includes("..") || !/^[A-Za-z0-9._/-]+$/.test(sub))) fail("The folder part of the link is not valid.");
  // Only a link that is plainly a repository is cloned on sight. The rest are
  // fetched first and judged by what comes back, so a direct download link
  // that ends in /download installs instead of failing as a bad repository.
  const plainlyGit = GIT_PLAIN.test(url) || /\.git$/i.test(url) || GIT_HOST.test(url) || !!m;
  return { kind: plainlyGit ? "git" : "web", url, ref, subdir: sub, display: raw };
}

function git(args, { cwd, timeout = 240 } = {}) {
  return new Promise((done) => execFile("git", args, { cwd, timeout: timeout * 1000, maxBuffer: 8 << 20,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "/bin/true" } },
  (err, out, errOut) => done({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, out: String(out || ""), err: String(errOut || err?.message || "") })));
}

async function fetchSource(source, dest) {
  if (source.kind === "archive") {
    try { return unpack(await download(source.url, `burrow/${HOST}`), dest); }
    catch (e) { if (e instanceof ArchiveError) fail(e.message); throw e; }
  }
  // A link that is neither plainly a repository nor named like an archive:
  // fetch it and look. Archives install; anything else (a repository served
  // over http, say) falls through to git, and if that fails too we say what
  // the server actually handed us.
  if (source.kind === "web") {
    const meta = {};
    let buf = null, why = null;
    try { buf = await download(source.url, `burrow/${HOST}`, meta); }
    catch (e) { why = e.message; }
    if (buf && isArchive(buf)) {
      try { return unpack(buf, dest); }
      catch (e) { if (e instanceof ArchiveError) fail(e.message); throw e; }
    }
    const r = await fetchGit(source, dest);
    if (r.ok) return r.commit;
    if (why) fail(why);                              // it already names the address and what went wrong
    // It answered, but with something that is not an addon. Say what it sent:
    // a file-sharing page instead of the link behind its download button is
    // the usual reason.
    const page = /^\s*</.test(String(buf?.subarray(0, 64) || "")) || /html|xml/i.test(meta.type || "");
    fail(page
      ? `Could not install from ${source.display}: that address answers with a web page${meta.type ? ` (${meta.type})` : ""}, not an addon. If it is a download page, use the link behind its download button.`
      : `Could not install from ${source.display}: what came back is not a .zip or .tar.gz${meta.type ? ` (${meta.type})` : ""}, and it is not a git repository either (${r.why}).`);
  }
  if (source.kind === "local") {
    cpSync(source.path, dest, { recursive: true, verbatimSymlinks: true,
      filter: (p) => !/(^|\/)(\.git|node_modules|__pycache__)$/.test(p) });
    return null;
  }
  const r = await fetchGit(source, dest);
  if (!r.ok) fail(`Could not fetch ${source.display}: ${r.why}`);
  return r.commit;
}

// -> {ok: true, commit} | {ok: false, why}
async function fetchGit(source, dest) {
  const base = ["clone", "--depth", "1", "--quiet", ...(source.ref ? ["--branch", source.ref] : [])];
  let r = { code: 1, err: "" };
  if (source.subdir) {
    r = await git([...base, "--filter=blob:none", "--sparse", source.url, dest]);
    if (r.code === 0) {
      r = await git(["sparse-checkout", "set", "--no-cone", `/${source.subdir}/`], { cwd: dest });
      if (r.code !== 0) rmSync(dest, { recursive: true, force: true });
    }
  }
  if (r.code !== 0) {
    rmSync(dest, { recursive: true, force: true });
    r = await git([...base, source.url, dest]);
  }
  if (r.code !== 0) {
    rmSync(dest, { recursive: true, force: true });
    let why = r.err.trim().split("\n").pop() || "git clone failed";
    if (/could not read Username|Authentication failed|not found/i.test(r.err)) why = "the repository was not found, or it is private";
    if (/ENOENT/.test(r.err)) why = "git is not installed on this machine";
    return { ok: false, why };
  }
  const h = await git(["rev-parse", "HEAD"], { cwd: dest, timeout: 20 });
  return { ok: true, commit: h.code === 0 ? h.out.trim().slice(0, 40) : null };
}

// ------------------------------------------------------------------ the manifest (same rules as Selkies Forge)
function inside(root, rel, what, mustExist = true) {
  if (typeof rel !== "string" || !rel.trim()) fail(`${what} must be a path inside the addon`);
  rel = rel.trim();
  if (rel.startsWith("/") || rel.replace(/\\/g, "/").split("/").includes("..")) fail(`${what} (${rel}) must be a relative path inside the addon`);
  const realRoot = realpathSync(root);
  let p;
  try { p = realpathSync(join(root, rel)); } catch { p = resolve(root, rel); }
  if (p !== realRoot && !p.startsWith(realRoot + sep)) fail(`${what} (${rel}) points outside the addon`);
  if (mustExist) { let f = false; try { f = statSync(p).isFile(); } catch { /* */ } if (!f) fail(`${what} (${rel}) does not exist`); }
  return rel;
}
function image(root, rel, what) {
  rel = inside(root, rel, what);
  if (!IMAGE_TYPES[extname(rel).toLowerCase()]) fail(`${what} must be .svg, .png, .webp or .jpg`);
  if (statSync(join(root, rel)).size > MAX_IMAGE) fail(`${what} is larger than ${MAX_IMAGE / 1024} KB`);
  return rel;
}
function text(d, key, limit, required = false) {
  const v = d[key];
  if (v == null || v === "") { if (required) fail(`forge-addon.json needs "${key}"`); return ""; }
  if (typeof v !== "string") fail(`"${key}" must be text`);
  if (v.trim().length > limit) fail(`"${key}" is longer than ${limit} characters`);
  return v.trim();
}
function url(v, what) {
  if (typeof v !== "string" || !/^https?:\/\/\S+$/.test(v.trim())) fail(`${what} must be an http(s) link`);
  return v.trim();
}
export function versionTuple(v) {
  const out = [];
  for (const part of String(v || "0").split(/[.+-]/)) { if (!/^\d+$/.test(part)) break; out.push(Number(part)); }
  while (out.length < 3) out.push(0);
  return out;
}
const vcmp = (a, b) => { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };

function coerce(st, v) {
  if (st.type === "bool") return typeof v === "string" ? ["1", "true", "yes", "on"].includes(v.trim().toLowerCase()) : !!v;
  if (st.type === "number") {
    const n = Number(v);
    if (v === "" || v == null || Number.isNaN(n)) fail(`${st.label} must be a number`);
    if (("min" in st && n < st.min) || ("max" in st && n > st.max)) fail(`${st.label} must be between ${st.min ?? n} and ${st.max ?? n}`);
    return n;
  }
  v = v == null ? "" : String(v);
  if (st.type === "select" && !st.options.some((o) => o.value === v)) fail(`${st.label}: pick one of the options`);
  if (v.length > 2000) fail(`${st.label} is too long`);
  return v;
}

// "update_card": how the host dresses this addon's update card (Weft). Read from
// the NEW version's manifest when an update is found, so each release can say
// what it brings. Every key is optional:
//   theme       green (default) | blue | red | orange | amber | purple | pink | teal | gray
//   accent      "#rrggbb": a colour of the addon's own (wins over theme)
//   style       glow (default) | solid | outline | minimal
//   urgency     normal | recommended | important | security | critical
//               (security/critical: red, a shield, a "install it soon" line)
//   badge       the chip beside the title (≤14 characters; "" for none; default NEW)
//   icon        download | shield | bolt | spark | heart | star | wrench | rocket | lock | bug
//   title       ≤80 characters, with {name}, {version}, {from}
//   tagline     ≤140 characters: one line under the title
//   highlights  up to 5 lines (≤100 characters each): what's new
//   button      ≤24 characters, with {version}
//   notes       an http(s) link to the release notes
export const CARD_THEMES = ["green", "blue", "red", "orange", "amber", "purple", "pink", "teal", "gray"];
export const CARD_STYLES = ["glow", "solid", "outline", "minimal"];
export const CARD_URGENCY = ["normal", "recommended", "important", "security", "critical"];
export const CARD_ICONS = ["download", "shield", "bolt", "spark", "heart", "star", "wrench", "rocket", "lock", "bug"];
export function cleanUpdateCard(c) {
  if (c == null) return null;
  if (typeof c !== "object" || Array.isArray(c)) fail('"update_card" must be an object');
  const out = {};
  const pick = (k, list) => { if (c[k] == null) return; if (!list.includes(c[k])) fail(`update_card.${k} must be one of ${list.join(", ")}`); out[k] = c[k]; };
  const str = (k, max) => { if (c[k] == null) return; if (typeof c[k] !== "string") fail(`update_card.${k} must be text`); if (c[k].trim().length > max) fail(`update_card.${k} is longer than ${max} characters`); out[k] = c[k].trim(); };
  pick("theme", CARD_THEMES); pick("style", CARD_STYLES); pick("urgency", CARD_URGENCY); pick("icon", CARD_ICONS);
  if (c.accent != null) { if (!/^#[0-9a-fA-F]{6}$/.test(String(c.accent))) fail('update_card.accent must look like "#ff5a52"'); out.accent = String(c.accent).toLowerCase(); }
  str("badge", 14); str("title", 80); str("tagline", 140); str("button", 24);
  if (c.highlights != null) {
    if (!Array.isArray(c.highlights) || c.highlights.length > 5 || !c.highlights.every((x) => typeof x === "string" && x.trim() && x.trim().length <= 100)) fail("update_card.highlights must be up to 5 lines of at most 100 characters");
    out.highlights = c.highlights.map((x) => x.trim());
  }
  if (c.notes != null) out.notes = url(c.notes, "update_card.notes");
  const unknown = Object.keys(c).filter((k) => !["theme", "accent", "style", "urgency", "badge", "icon", "title", "tagline", "highlights", "button", "notes"].includes(k));
  if (unknown.length) fail(`update_card: unknown key "${unknown[0]}"`);
  return Object.keys(out).length ? out : null;
}

// requires.root: why install/update/uninstall need root, shown to the user before they run.
export function rootReason(v) {
  if (v == null) return "";
  if (typeof v !== "string" || !v.trim()) fail('requires.root must be text: why the addon needs root, e.g. "Installs and configures Postfix"');
  if (v.trim().length > 200) fail("requires.root is longer than 200 characters");
  return v.trim();
}

export function loadManifest(root) {
  const path = join(root, MANIFEST);
  let size;
  try { size = statSync(path).size; } catch { fail(`No ${MANIFEST} here. An addon needs one at its root (see the Addons docs).`); }
  if (size > MAX_MANIFEST) fail(`${MANIFEST} is larger than 64 KB`);
  let d;
  try { d = JSON.parse(readFileSync(path, "utf8")); } catch (e) { fail(`${MANIFEST} is not valid JSON: ${e.message}`); }
  if (!d || typeof d !== "object" || Array.isArray(d)) fail(`${MANIFEST} must be a JSON object`);
  if (d.spec !== SPEC) {
    if (Number.isInteger(d.spec) && d.spec > SPEC) fail(`This addon needs a newer Burrow (addon spec ${d.spec}; this one reads ${SPEC}).`);
    fail(`forge-addon.json needs "spec": ${SPEC}`);
  }
  const m = { spec: SPEC };
  m.id = text(d, "id", 40, true);
  if (!ID_RE.test(m.id)) fail('"id" must be 2-40 lowercase letters, digits or dashes, starting with a letter or digit');
  m.name = text(d, "name", 60, true);
  m.version = text(d, "version", 30, true);
  m.description = text(d, "description", 600);
  m.author = text(d, "author", 80);
  m.license = text(d, "license", 40);
  m.homepage = d.homepage ? url(d.homepage, '"homepage"') : "";
  m.logo = d.logo ? image(root, d.logo, '"logo"') : "";
  m.update_card = cleanUpdateCard(d.update_card);

  const scripts = d.scripts;
  if (!scripts || typeof scripts !== "object" || !scripts.install) fail('forge-addon.json needs "scripts": {"install": "..."}');
  m.scripts = {};
  for (const [k, v] of Object.entries(scripts)) {
    if (!SCRIPTS.includes(k)) fail(`unknown script "${k}" (known: ${SCRIPTS.join(", ")})`);
    m.scripts[k] = inside(root, v, `scripts.${k}`);
  }
  m.actions = [];
  for (const a of d.actions || []) {
    if (!a || typeof a !== "object" || !ACTION_RE.test(String(a.id || ""))) fail('every action needs an "id" (lowercase letters, digits, dashes)');
    if (SCRIPTS.includes(a.id)) fail(`action "${a.id}" has the name of a lifecycle script`);
    if (a.root != null && typeof a.root !== "boolean") fail(`actions.${a.id}.root must be true or false`);
    m.actions.push({ id: a.id, label: text(a, "label", 24, true), script: inside(root, a.script, `actions.${a.id}.script`), confirm: text(a, "confirm", 200), root: a.root === true });
  }
  if (m.actions.length > 8) fail("at most 8 actions");
  m.settings = [];
  const seen = new Set();
  for (const s of d.settings || []) {
    if (!s || typeof s !== "object" || !SETTING_RE.test(String(s.key || ""))) fail('every setting needs a "key" in CAPITALS (A-Z, 0-9, _), e.g. PORT');
    if (seen.has(s.key)) fail(`setting ${s.key} appears twice`);
    seen.add(s.key);
    const type = s.type || "text";
    if (!SETTING_TYPES.includes(type)) fail(`setting ${s.key}: type must be one of ${SETTING_TYPES.join(", ")}`);
    const st = { key: s.key, type, label: text(s, "label", 60, true), help: text(s, "help", 300), default: s.default ?? null, required: !!s.required };
    if (type === "number") for (const k of ["min", "max"]) if (s[k] != null) st[k] = Number(s[k]);
    if (type === "select") {
      st.options = (s.options || []).map((o) => (o && typeof o === "object" ? o : { value: o, label: o }))
        .map((o) => ({ value: String(o.value), label: String(o.label ?? o.value).slice(0, 60) }));
      if (!st.options.length) fail(`setting ${s.key}: a select needs "options"`);
    }
    if (s.icon) st.icon = image(root, s.icon, `setting ${s.key} icon`);
    if (st.default != null) st.default = coerce(st, st.default);
    m.settings.push(st);
  }
  if (m.settings.length > 16) fail("at most 16 settings");

  if (d.platforms == null) m.platforms = [...PLATFORMS];
  else {
    if (!Array.isArray(d.platforms) || !d.platforms.length || !d.platforms.every((x) => typeof x === "string")) fail('"platforms" must be a list, e.g. ["selkies-forge", "burrow"]');
    const bad = d.platforms.find((x) => !PLATFORMS.includes(x));
    if (bad) fail(`unknown platform "${bad}" (known: ${PLATFORMS.join(", ")})`);
    m.platforms = PLATFORMS.filter((x) => d.platforms.includes(x));
  }
  const req = d.requires || {};
  if (typeof req !== "object" || Array.isArray(req)) fail('"requires" must be an object');
  m.requires = {
    forge: String(req.forge || "").trim(), burrow: String(req.burrow || "").trim(),
    os: (req.os || []).map((x) => String(x).toLowerCase()),
    arch: (req.arch || []).map((x) => ARCH_ALIASES[String(x).toLowerCase()] || String(x).toLowerCase()),
    commands: (req.commands || []).map(String).filter((x) => /^[A-Za-z0-9._+-]+$/.test(x)),
  };
  for (const h of ["forge", "burrow"]) if (m.requires[h] && !/^(>=)?\s*\d+(\.\d+){0,2}$/.test(m.requires[h])) fail(`requires.${h} must look like ">=1.10.0"`);
  m.requires.root = rootReason(req.root);
  m.integration = {};
  if (d.integration && Object.keys(d.integration).length) {
    const p = String(d.integration.dir || "");
    if (!(p.startsWith("~/") || p.startsWith("$HOME/")) || p.split("/").includes("..")) fail("integration.dir must be a folder under ~/ (e.g. ~/.config/myapp/integrations)");
    m.integration = { dir: p };
  }
  const rep = d.replaces || [];
  if (!Array.isArray(rep) || rep.length > 8 || !rep.every((x) => typeof x === "string" && ID_RE.test(x))) fail('"replaces" must be a list of addon ids, e.g. ["old-name"]');
  m.replaces = rep.filter((x) => x !== m.id);
  m.links = [];
  for (const ln of (d.links || []).slice(0, 6)) if (ln && typeof ln === "object") m.links.push({ label: text(ln, "label", 40, true), url: url(ln.url, "link url") });
  // Burrow's own field (other hosts ignore it): code that runs inside Burrow
  // while the addon is installed, and a panel for the Burrow page.
  //   "burrow": {"extension": "burrow/extension.mjs", "ui": "burrow/ui.js"}
  m.burrow = null;
  if (d.burrow && typeof d.burrow === "object") {
    m.burrow = {};
    if (d.burrow.extension) m.burrow.extension = inside(root, d.burrow.extension, "burrow.extension");
    if (d.burrow.ui) m.burrow.ui = inside(root, d.burrow.ui, "burrow.ui");
  }
  return m;
}

const haveCmd = (c) => String(process.env.PATH || "").split(":").some((d) => { try { return statSync(join(d, c)).isFile(); } catch { return false; } });
const machine = () => { const a = { x64: "x86_64", arm64: "aarch64", arm: "armv7l", ia32: "i686" }[osArch()] || osArch(); return ARCH_ALIASES[a] || a; };

export function checkRequirements(m, hostVersion) {
  const out = [];
  if (!(m.platforms || PLATFORMS).includes(HOST)) out.push(`is made for ${m.platforms.map((p) => (p === "selkies-forge" ? "Selkies Forge" : p)).join(" and ")}, not Burrow`);
  const r = m.requires;
  if (r.burrow) {
    const want = versionTuple(r.burrow.replace(/^>=\s*/, ""));
    if (vcmp(versionTuple(hostVersion), want) < 0) out.push(`needs Burrow ${want.join(".")} or newer (this is ${hostVersion})`);
  }
  const sys = osPlatform();
  if (r.os.length && !r.os.includes(sys)) out.push(`runs on ${r.os.join(", ")}, not ${sys}`);
  if (r.arch.length && !r.arch.includes(machine())) out.push(`has no build for ${machine()} (it supports ${r.arch.join(", ")})`);
  const missing = r.commands.filter((c) => !haveCmd(c));
  if (missing.length) out.push(`needs ${missing.join(", ")} installed`);
  return out;
}

// Where an addon listens: the host of the address its status reports, or loopback.
function listenHost(st) {
  try { const h = new URL(st.url).hostname; if (h && h !== "0.0.0.0") return h.replace(/^\[|\]$/g, ""); } catch { /* */ }
  return "127.0.0.1";
}

function lastJson(lines) {
  for (let i = lines.length - 1; i >= 0; i--) {
    const l = lines[i].trim();
    if (l.startsWith("{") && l.endsWith("}")) { try { const v = JSON.parse(l); if (v && typeof v === "object") return v; } catch { /* */ } }
  }
  return {};
}

// ------------------------------------------------------------------ jobs
class Job {
  constructor(aid, kind, label) {
    Object.assign(this, { id: randomBytes(6).toString("hex"), aid, kind, label, state: "running", phase: label, progress: 0.02,
                          lines: [], base: 0, started: Date.now(), finished: null, result: null, error: null, procs: new Set() });
  }
  log(line, cls) { this.lines.push({ t: Date.now(), line: String(line).slice(0, 2000), cls: cls || "" }); if (this.lines.length > 1500) { this.lines.splice(0, 500); this.base += 500; } }
  view(since = 0) {
    const from = Math.max(0, since - this.base);
    return { id: this.id, aid: this.aid, kind: this.kind, label: this.label, state: this.state, phase: this.phase, progress: this.progress,
             started: this.started, finished: this.finished, result: this.result, error: this.error, terminal: !!this.terminal,
             next: this.base + this.lines.length, lines: this.lines.slice(from) };
  }
  cancel() {
    if (this.state !== "running") return;
    this.cancelled = true;
    for (const p of this.procs) { try { process.kill(-p.pid, "SIGTERM"); } catch { /* */ } }
    this.terminal?.finish?.(130, "cancelled from the dashboard");           // the terminal hears it on its next line
  }
}

// ------------------------------------------------------------------ the host
const KEEP_VERSIONS = 3;          // an addon's checkouts before its last updates, for Roll back

export class Addons {
  // dir:      where checkouts and data live (AEGIS_HOME/addons)
  // registry: the JSON file that remembers them (DATA/addons.json)
  // env:      () => {ADDON_HOST_URL, ADDON_BIND, BURROW_SOCKET, …}: host values for scripts
  // notify:   (notice) => …: the bell, for what an automatic path skipped (root)
  // root:     a RootAccess (burrow/root.mjs): sudo checks and the askpass tokens
  constructor({ dir, registry, version, env, log, tunnels, onChange, notify, root, terminalTtl }) {
    this.terminalTtl = terminalTtl || TERMINAL_TTL;
    Object.assign(this, { dir, registryFile: registry, version, hostEnv: env || (() => ({})), log: log || console.log, tunnels, onChange, notify: notify || null });
    this.root = root || new RootAccess();
    this.statusCache = new Map();
    this.jobs = new Map();
    this.scanCache = null;
    this.expectUntil = new Map();   // aid -> until when a stop is Burrow's own doing
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  // ---------------- registry
  load() { try { return JSON.parse(readFileSync(this.registryFile, "utf8")).addons || {}; } catch { return {}; } }
  save(all) {
    const tmp = `${this.registryFile}.tmp.${process.pid}`;
    mkdirSync(dirname(this.registryFile), { recursive: true });
    writeFileSync(tmp, JSON.stringify({ spec: SPEC, host: HOST, addons: all }, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.registryFile);
  }
  get(id) { const r = this.load()[id]; if (!r) fail(`No addon called ${id}.`); return r; }
  patch(id, p) { const all = this.load(); if (!all[id]) fail(`No addon called ${id}.`); Object.assign(all[id], p); this.save(all); return all[id]; }
  addonDir(id) { return join(this.dir, id); }
  rootOf(rec) { return join(this.addonDir(rec.id), "repo", rec.subdir || ""); }
  dataDir(rec) { const d = join(this.addonDir(rec.id), "data"); mkdirSync(d, { recursive: true, mode: 0o700 }); return d; }

  // ---------------- scripts
  env(rec, root, data, extra = {}) {
    const m = rec.manifest;
    const e = { ...process.env };
    for (const k of ROOT_VARS) delete e[k];                // root comes only from a grant (extra), never inherited
    Object.assign(e, { ADDON_SPEC: String(SPEC), ADDON_ID: m.id, ADDON_NAME: m.name, ADDON_VERSION: m.version,
                ADDON_DIR: root, ADDON_DATA: data, ADDON_ADOPT: "0", ADDON_UPDATE: "0", ADDON_ARCH: machine(), ADDON_ROOT: "0",
                ADDON_HOST: HOST, ADDON_HOST_VERSION: this.version, ...this.hostEnv() });
    for (const st of m.settings) {
      let v = (rec.settings || {})[st.key] ?? st.default;
      v = v == null ? "" : st.type === "bool" ? (v ? "1" : "0") : String(v);
      e["ADDON_SETTING_" + st.key] = v;
    }
    Object.assign(e, extra);
    // the older names, for scripts written for Selkies Forge first
    for (const k of Object.keys(e)) if (k.startsWith("ADDON_") && !k.startsWith("ADDON_HOST") && !NO_TWIN.has(k)) e["FORGE_" + k] = e[k];
    if (e.ADDON_BIND) e.FORGE_BIND = e.ADDON_BIND;
    return e;
  }

  run(rec, rel, { job, extra, timeout = 600, root, data } = {}) {
    root = root || this.rootOf(rec);
    data = data || this.dataDir(rec);
    if (job?.terminal) return this.runInTerminal(job, rec, rel, { extra, root, data });
    return new Promise((done) => {
      // A job (install, update, an action like "start") runs in a scope of its
      // own under the user's systemd: what it starts (Selkies Forge's web UI)
      // then outlives this process, which a service manager may stop with
      // everything in its cgroup (KillMode=control-group) on every restart.
      const env = this.env(rec, root, data, extra);
      const scope = job ? userScope() : null;
      const [cmd, args] = scope ? ["systemd-run", [...scope.args, "--", "bash", join(root, rel)]] : ["bash", [join(root, rel)]];
      const p = spawn(cmd, args, { cwd: root, env: scope ? { ...env, ...scope.env } : env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
      job?.procs.add(p);
      const lines = [], dir = { open: null, warn: [] };
      let killed = null, buf = "";
      const t = setTimeout(() => { killed = `timed out after ${timeout}s`; try { process.kill(-p.pid, "SIGTERM"); } catch { /* */ } setTimeout(() => { try { process.kill(-p.pid, "SIGKILL"); } catch { /* */ } }, 5000); }, timeout * 1000);
      const feed = (chunk) => {
        buf += chunk;
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i).replace(/\r$/, ""); buf = buf.slice(i + 1);
          if (line.startsWith("::")) { this.directive(line, job, dir); continue; }
          lines.push(line); if (lines.length > 400) lines.splice(0, 100);
          job?.log(line);
        }
      };
      p.stdout.setEncoding("utf8"); p.stderr.setEncoding("utf8");
      p.stdout.on("data", feed); p.stderr.on("data", feed);
      p.on("error", (e) => { lines.push(e.message); });
      p.on("close", (code) => {
        clearTimeout(t); job?.procs.delete(p);
        if (buf) feed("\n");
        if (killed || job?.cancelled) { const why = killed || "cancelled"; lines.push(why); job?.log(why, "err"); }
        done({ code: killed ? 124 : job?.cancelled ? 130 : (code ?? 1), lines, dir });
      });
    });
  }
  // The script step of a terminal job: handed to the CLI as a run spec, and
  // finished by what it reports (line…, done). -> the same {code, lines, dir} as run()
  runInTerminal(job, rec, rel, { extra, root, data }) {
    const T = job.terminal;
    const env = this.env(rec, root, data, { ...extra, ADDON_ROOT: "1" });
    // only the addon's own variables: the terminal keeps its own PATH, HOME, TERM…
    const host = new Set(Object.keys(this.hostEnv()));
    const own = Object.fromEntries(Object.entries(env).filter(([k]) => /^(ADDON_|FORGE_|BURROW_)/.test(k) || host.has(k)));
    for (const k of ["ADDON_ASKPASS_TOKEN", "FORGE_ADDON_ASKPASS_TOKEN", "SUDO_ASKPASS"]) delete own[k];
    return new Promise((done) => {
      const lines = [], dir = { open: null, warn: [] };
      T.spec = { script: join(root, rel), cwd: root, env: own };
      T.feed = (line) => {
        line = String(line).replace(/\r$/, "").slice(0, 2000);
        if (line.startsWith("::")) return this.directive(line, job, dir);
        lines.push(line); if (lines.length > 400) lines.splice(0, 100);
        job.log(line);
      };
      T.finish = (code, why) => {
        if (T.closed) return;
        T.closed = true; clearTimeout(T.timer);
        if (why) { lines.push(why); job.log(why, "err"); }
        done({ code: Number.isInteger(code) ? code : 1, lines, dir });
      };
      T.timer = setTimeout(() => T.finish(124, "the terminal never said it was done (two hours)"), Math.max(1000, T.expires - Date.now()));
      T.timer.unref?.();
      job.phase = "Running in your terminal";
      T.ready?.();
    });
  }
  // POST /addons/<id>/runspec {op, action?, keep_data?, settings?} (control socket only):
  // makes the job and waits until it reaches its script -> {job, token, script, cwd, env, expires},
  // or {job, done: true} when it needed none (an update of an addon that isn't installed…).
  async terminalRun(id, b = {}) {
    const op = b.op, rec = this.get(id);
    if (!["install", "update", "uninstall", "action", "rollback"].includes(op)) fail("op is install, update, uninstall, rollback or action");
    if (!this.rootNeed(rec, op, b.action)) fail(`${rec.manifest.name} doesn't need root to ${op === "action" ? `run ${b.action}` : op}: it runs in Aegis (aegis addons ${op} ${id}${op === "action" ? ` ${b.action}` : ""}).`);
    const T = { token: randomBytes(32).toString("hex"), expires: Date.now() + this.terminalTtl, spec: null, closed: false };
    const ready = new Promise((r) => { T.ready = r; });
    const view = this.runOp(op, id, b, null, { terminal: T });
    const job = this.jobs.get(view.id);
    const t = setTimeout(() => T.ready(), 10 * 60e3);                    // fetching an update can take a while, not forever
    await ready; clearTimeout(t);
    if (!T.spec) {
      if (job.state === "running") { job.cancel(); fail("It took too long to get ready (fetching the new version?). Try again."); }
      return { job: job.view(1e9), done: true };
    }
    this.log(`addon ${id}: ${op} handed to the terminal (job ${job.id})`);
    return { job: job.view(0), token: T.token, script: T.spec.script, cwd: T.spec.cwd, env: T.spec.env, expires: T.expires };
  }
  // what the terminal reports: only with the job's token, only while it runs
  terminalOf(jobId, token) {
    const job = this.job(jobId), T = job.terminal;
    if (!T || typeof token !== "string" || token.length !== T.token.length || !timingSafeEqual(Buffer.from(token), Buffer.from(T.token))) {
      throw Object.assign(new AddonError("That isn't this job's token."), { status: 403 });
    }
    if (T.closed || !T.spec) throw Object.assign(new AddonError(job.cancelled ? "Cancelled from the dashboard." : "This job isn't waiting for its terminal any more."), { status: 410 });
    return { job, T };
  }
  terminalLines(jobId, { token, lines } = {}) {
    const { job, T } = this.terminalOf(jobId, token);
    for (const l of (Array.isArray(lines) ? lines : []).slice(0, 500)) T.feed(l);
    return { ok: true, state: job.state, phase: job.phase, progress: job.progress };
  }
  terminalDone(jobId, { token, code } = {}) {
    const { T } = this.terminalOf(jobId, token);
    T.finish(Number(code));
    return { ok: true };
  }
  directive(line, job, out) {
    const [word, ...rest] = line.slice(2).split(" ");
    const arg = rest.join(" ").trim();
    if (word === "progress") {
      const [pct, ...label] = arg.split(" ");
      const v = Number(pct);
      if (!Number.isNaN(v) && job) { job.progress = Math.max(0, Math.min(100, v)) / 100; if (label.length) job.phase = label.join(" ").slice(0, 120); }
    } else if (word === "phase" && job) job.phase = arg.slice(0, 120) || "working";
    else if (word === "open" && /^https?:\/\/\S+$/.test(arg)) out.open = arg;
    else if (word === "warn") { out.warn.push(arg.slice(0, 300)); job?.log(arg, "err"); }
  }

  async detect(rec, at) {
    const s = rec.manifest.scripts.detect;
    if (!s) return { found: false };
    const r = await this.run(rec, s, { timeout: TIMEOUT.detect, ...(at || {}) });
    if (r.code !== 0) return { found: false };
    const i = lastJson(r.lines);
    // A detect script says so in its JSON ({"found": false}); exiting 0 with
    // nothing to say still counts as found, the way the first ones did.
    if (i.found === false || i.found === "false") return { found: false };
    return { found: true, version: String(i.version || "").slice(0, 30), url: /^https?:\/\/\S+$/.test(i.url || "") ? i.url : null,
             detail: String(i.detail || "").slice(0, 200) };
  }

  async status(rec, maxAge = 8000) {
    if (!rec.installed) return { state: "not-installed" };
    const s = rec.manifest.scripts.status;
    if (!s) return { state: "installed", url: rec.open_url };
    const hit = this.statusCache.get(rec.id);
    if (hit && Date.now() - hit.at < maxAge) return hit.value;
    let st;
    try {
      const r = await this.run(rec, s, { timeout: TIMEOUT.status });
      const i = lastJson(r.lines);
      st = { state: String(i.state || (r.code === 0 ? "installed" : "error")).slice(0, 20),
             url: /^https?:\/\/\S+$/.test(i.url || "") ? i.url : rec.open_url, version: String(i.version || "").slice(0, 30),
             detail: String(i.detail || "").slice(0, 200) };
      if (typeof i.name === "string" && i.name.trim()) st.name = i.name.trim().slice(0, 60);
      const port = Number(i.port);
      if (port > 0 && port < 65536) st.port = port;
    } catch (e) { st = { state: "error", detail: e.message, url: rec.open_url }; }
    this.statusCache.set(rec.id, { at: Date.now(), value: st });
    return st;
  }

  // ---------------- the operations
  async add(text) {
    const source = parseSource(text);
    const tmp = mkdtempSync(join(this.dir, ".add-"));
    try {
      const commit = await fetchSource(source, join(tmp, "repo"));
      const root = join(tmp, "repo", source.subdir || "");
      if (!existsSync(root)) fail(`The repository has no folder ${source.subdir}.`);
      const m = loadManifest(root);
      const all = this.load();
      const old = all[m.id];
      if (old && old.source?.display !== source.display && old.installed) fail(`${m.name} is already installed from ${old.source.display}. Uninstall it before adding another copy.`);
      const dest = this.addonDir(m.id);
      mkdirSync(dest, { recursive: true });
      rmSync(join(dest, "repo"), { recursive: true, force: true });
      renameSync(join(tmp, "repo"), join(dest, "repo"));
      const rec = { installed: false, settings: {}, added: Date.now(), ...(old || {}), id: m.id, source, subdir: source.subdir || "", commit, manifest: m, updated: Date.now() };
      all[m.id] = rec;
      this.save(all);
      rec.detected = await this.detect(rec);
      this.patch(rec.id, { detected: rec.detected });
      this.statusCache.delete(rec.id);
      this.scanCache = null;
      return this.view(rec);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  }

  // Look at an addon without adding it or running anything: fetch it to a
  // scratch folder, validate forge-addon.json, return its metadata.
  async inspect(text) {
    const source = parseSource(text);
    const tmp = mkdtempSync(join(this.dir, ".inspect-"));
    try {
      const commit = await fetchSource(source, join(tmp, "repo"));
      const root = join(tmp, "repo", source.subdir || "");
      if (!existsSync(root)) fail(`There is no folder ${source.subdir} in it.`);
      const m = loadManifest(root);
      let logo = null;
      if (m.logo) { const p = join(root, m.logo); if (statSync(p).size <= 65536) logo = `data:${IMAGE_TYPES[extname(p).toLowerCase()]};base64,${readFileSync(p).toString("base64")}`; }
      let files = 0;
      const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(join(d, e.name)) : files++; };
      walk(root);
      const pick = (o, ks) => Object.fromEntries(ks.map((k) => [k, o[k]]));
      return { valid: true, source: pick(source, ["kind", "url", "ref", "subdir", "display", "format"]), commit,
               manifest: pick(m, ["id", "name", "version", "description", "author", "license", "homepage", "platforms", "replaces", "requires", "links"]),
               scripts: Object.keys(m.scripts).sort(), actions: m.actions.map((a) => a.label), settings: m.settings.map((x) => x.key),
               integration: m.integration.dir || null, logo, files, problems: checkRequirements(m, this.version), registered: !!this.load()[m.id] };
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  }

  cleanSettings(rec, given = {}) {
    const out = {}, old = rec.settings || {};
    for (const st of rec.manifest.settings) {
      let v;
      if (st.key in given && !(st.type === "password" && [null, "", MASK].includes(given[st.key]))) v = coerce(st, given[st.key]);
      else if (st.key in old) v = old[st.key];
      else v = st.default;
      if (st.required && (v == null || v === "")) fail(`${st.label} is required`);
      out[st.key] = v;
    }
    return out;
  }

  // ---------------- root (burrow/root.mjs)
  // Why this operation needs root, or "" when it doesn't.
  rootNeed(rec, op, actionId) {
    const m = rec.manifest, why = m.requires?.root || "";
    if (op === "install") return why;
    // the update runs the NEW version's script: its manifest, as the last check read it
    if (op === "update") return rec.installed ? (typeof rec.remote?.root === "string" ? rec.remote.root : why) : "";
    if (op === "uninstall") return rec.installed && m.scripts.uninstall ? why : "";
    if (op === "rollback") return rec.installed ? why : "";
    if (op === "action") { const a = m.actions.find((x) => x.id === actionId); return a?.root ? why || `"${a.label}" needs administrator access` : ""; }
    return "";
  }
  // What the dashboard and the command line ask before a root job: cheap (one `sudo -n`, cached a minute).
  async rootInfo(id) {
    const rec = this.get(id), m = rec.manifest;
    const needs = { install: !!this.rootNeed(rec, "install"), update: !!this.rootNeed(rec, "update"), uninstall: !!this.rootNeed(rec, "uninstall"),
                    actions: m.actions.filter((a) => a.root).map((a) => a.id) };
    const any = needs.install || needs.update || needs.uninstall || needs.actions.length > 0;
    const out = { id, name: m.name, homepage: m.homepage || null, logo: m.logo ? `/__gate/api/addons/${rec.id}/image?v=${(rec.commit || String(rec.updated || 0)).slice(0, 12)}` : null,
                  reason: this.rootNeed(rec, "install") || this.rootNeed(rec, "update") || (needs.actions.length ? this.rootNeed(rec, "action", needs.actions[0]) : ""),
                  needsRoot: any, needs, start: this.startAction(rec)?.id || null, sudo: null, passwordless: null, why: null,
                  busy: [...this.jobs.values()].find((j) => j.aid === rec.id && j.state === "running")?.view(1e9) || null };
    if (any) Object.assign(out, await this.root.check());
    // where Aegis can't get root, the terminal can: the commands for it
    out.commands = { install: terminalCommand(id, "install"), update: terminalCommand(id, "update"), uninstall: terminalCommand(id, "uninstall"),
                     actions: Object.fromEntries(needs.actions.map((a) => [a, terminalCommand(id, "action", a)])) };
    if (out.sudo === false) out.hint = terminalHint(m, terminalCommand(id, "install"));
    return out;
  }
  // Before a root job: null when the operation doesn't need root, else a grant
  // ({token}) once sudo is passwordless or the password checks out. Throws a
  // RootError: 428 {needsRoot, passwordless: false} without a password,
  // 403 {badPassword} for a wrong one, 403 {noSudo} when sudo can't work here.
  async rootGrant(id, op, { password, action } = {}) {
    const rec = this.get(id), reason = this.rootNeed(rec, op, action);
    if (!reason) return null;
    const cmd = terminalCommand(id, op, action), m = rec.manifest, base = { needsRoot: true, id, name: m.name, reason, homepage: m.homepage || null, command: cmd };
    const c = await this.root.check(true);
    if (!c.sudo) throw new RootError(`${m.name} needs administrator (root) access, and Aegis can't get it itself: ${c.why} ${terminalHint(m, cmd)}`, 403, { ...base, noSudo: true, sudo: false, passwordless: false, why: c.why, hint: terminalHint(m, cmd) });
    if (c.passwordless) return { token: this.root.issue(null), reason };
    if (password == null || password === "") throw new RootError(`${m.name} needs administrator (root) access: ${reason}. Type your password for sudo.`, 428, { ...base, sudo: true, passwordless: false });
    try { await this.root.validate(password); }
    catch (e) {
      if (e instanceof RootError) { Object.assign(e.extra, base, { sudo: !e.extra.noSudo, passwordless: false }); if (e.extra.noSudo) { e.extra.hint = terminalHint(m, cmd); e.message += " " + terminalHint(m, cmd); } }
      throw e;
    }
    return { token: this.root.issue(String(password)), reason };
  }
  // Nothing that needs root runs without a grant: an automatic path (default
  // addons, the watchdog, the bridge) gets this instead, and the bell says so.
  refuseRoot(rec, op, reason, actionLabel) {
    const m = rec.manifest, what = op === "action" ? `run "${actionLabel}"` : op;
    this.notify?.({ level: "warn", key: `root-${rec.id}-${op}`, title: `${m.name} needs administrator access to ${what}`,
      body: `${reason}. Nothing ran. ${op === "action" ? "Run it" : `${op[0].toUpperCase()}${op.slice(1)} it`} from Burrow → Addons, or in a terminal on this machine: ${terminalCommand(rec.id, op, rec.manifest.actions.find((a) => a.label === actionLabel)?.id)}.`,
      link: "/__gate/tunnels#/addons" });
    fail(`${m.name} needs administrator (root) access to ${what}: ${reason}. Nothing ran.`);
  }
  // install / update / uninstall / action, with the grant rootGrant gave (or null):
  // the dashboard's and the control socket's one way in. A grant is dropped
  // if the job never starts, and when it ends.
  runOp(op, id, b = {}, grant = null, { terminal = null } = {}) {
    try {
      if (op === "install") return this.install(id, b.settings, { root: grant, terminal });
      if (op === "update") return this.update(id, { root: grant, terminal });
      if (op === "uninstall") return this.uninstall(id, b.keep_data !== false, { root: grant, terminal });
      if (op === "rollback") return this.rollback(id, b.version || null, { root: grant, terminal });
      if (op === "action") return this.action(id, b.action, { root: grant, terminal });
      fail(`unknown operation ${op}`);
    } catch (e) { if (grant) this.root.drop(grant.token); throw e; }
  }
  rootEnv(grant) { return grant ? this.root.env(grant.token) : {}; }

  startJob(aid, kind, label, work, grant = null, terminal = null) {
    for (const j of this.jobs.values()) if (j.aid === aid && j.state === "running") fail(`${label.split(" ").pop()} is busy: ${j.label}.`);
    const job = new Job(aid, kind, label);
    this.jobs.set(job.id, job);
    if (terminal) job.terminal = terminal;
    if (grant) { this.root.bind(grant.token, job.id); job.root = true; }
    // whatever Burrow runs (stop, update, uninstall…) may take the addon down: that's no crash
    this.expectUntil.set(aid, Infinity);
    for (const [id, j] of this.jobs) if (j.state !== "running" && Date.now() - j.started > 3600e3) this.jobs.delete(id);
    Promise.resolve().then(() => work(job)).then((res) => {
      Object.assign(job, { state: "done", result: res || null, progress: 1, phase: "done" });
    }).catch((e) => {
      Object.assign(job, { state: job.cancelled ? "cancelled" : "error", error: e.message });
      job.log(e.message, "err");
    }).finally(() => { if (grant) this.root.drop(grant.token); if (job.terminal) { job.terminal.closed = true; clearTimeout(job.terminal.timer); job.terminal.ready?.(); } job.finished = Date.now(); this.expectUntil.set(aid, Date.now() + 30e3); this.statusCache.delete(aid); this.scanCache = null; this.log(`addon ${aid}: ${kind} ${job.state}`); this.onChange?.(aid); });
    return job.view();
  }

  install(id, settings, { root: grant = null, terminal = null } = {}) {
    const rec0 = this.get(id), m = rec0.manifest;
    const problems = checkRequirements(m, this.version);
    if (problems.length) fail(`${m.name} ${problems.join("; ")}.`);
    const why = this.rootNeed(rec0, "install");
    if (why && !grant && !terminal) this.refuseRoot(rec0, "install", why);
    const rec = this.patch(id, { settings: this.cleanSettings(rec0, settings || {}) });
    return this.startJob(id, "install", `Installing ${m.name}`, async (job) => {
      const found = await this.detect(rec);
      const adopt = found.found && !rec.installed;
      job.phase = adopt ? `Linking the ${m.name} already on this machine` : `Installing ${m.name}`;
      if (adopt) job.log(`${m.name} is already on this machine${found.detail ? ` (${found.detail})` : ""}; linking it.`);
      const r = await this.run(rec, m.scripts.install, { job, extra: { ADDON_ADOPT: adopt ? "1" : "0", ...this.rootEnv(grant) }, timeout: TIMEOUT.install });
      if (r.code !== 0) fail(`the install script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
      const done = this.patch(id, { installed: true, installed_version: m.version, installed_at: Date.now(), adopted: !!adopt,
                                    open_url: r.dir.open || found.url || rec.open_url || null, detected: found });
      return { id, name: m.name, open_url: done.open_url, adopted: !!adopt, warnings: r.dir.warn };
    }, grant, terminal);
  }

  update(id, { root: grant = null, terminal = null } = {}) {
    const rec = this.get(id);
    const why = this.rootNeed(rec, "update");
    if (why && !grant && !terminal) this.refuseRoot(rec, "update", why);
    return this.startJob(id, "update", `Updating ${rec.manifest.name}`, async (job) => {
      job.phase = `Fetching ${rec.manifest.name}`;
      const tmp = mkdtempSync(join(this.dir, ".upd-"));
      let m, commit;
      try {
        commit = await fetchSource(rec.source, join(tmp, "repo"));
        m = loadManifest(join(tmp, "repo", rec.source.subdir || ""));
        if (m.id !== id) fail(`the repository now holds a different addon (${m.id})`);
        // the new version needs root and nobody gave it: nothing changes, and the next try asks
        if (rec.installed && m.requires.root && !grant && !terminal) {
          this.patch(id, { remote: { ...(this.get(id).remote || {}), root: m.requires.root } });
          fail(`${m.name} ${m.version} needs administrator (root) access to update: ${m.requires.root}. Nothing changed; update it again to give it.`);
        }
        const dest = this.addonDir(id);
        rmSync(join(dest, "repo.old"), { recursive: true, force: true });
        if (existsSync(join(dest, "repo"))) renameSync(join(dest, "repo"), join(dest, "repo.old"));
        renameSync(join(tmp, "repo"), join(dest, "repo"));
        // the old copy is kept (versions/, for Roll back); run in a terminal, it
        // also comes back (code and registry) when that run doesn't succeed
      } finally { rmSync(tmp, { recursive: true, force: true }); }
      job.log(`${m.name} ${rec.manifest.version} -> ${m.version}${commit ? ` (${commit.slice(0, 10)})` : ""}`);
      const before = { manifest: rec.manifest, commit: rec.commit, updated: rec.updated, remote: rec.remote || null };
      let cur = this.patch(id, { manifest: m, commit, updated: Date.now(), remote: null, hold: null });
      const res = { id, name: m.name, version: m.version, ran: null };
      const dest = this.addonDir(id);
      try {
        if (cur.installed) {
          const script = m.scripts.update || m.scripts.install;
          res.ran = m.scripts.update ? "update" : "install";
          job.phase = `Updating ${m.name}`; job.progress = 0.2;
          const r = await this.run(cur, script, { job, extra: { ADDON_UPDATE: "1", ADDON_ADOPT: "1", ...(m.requires.root ? this.rootEnv(grant) : {}) }, timeout: TIMEOUT.update });
          if (r.code !== 0) fail(`the update script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
          cur = this.patch(id, { installed_version: m.version, open_url: r.dir.open || cur.open_url });
          res.open_url = cur.open_url;
        }
      } catch (e) {
        if (terminal && existsSync(join(dest, "repo.old"))) {
          rmSync(join(dest, "repo"), { recursive: true, force: true });
          renameSync(join(dest, "repo.old"), join(dest, "repo"));
          this.patch(id, before);
          job.log(`${before.manifest.name} ${before.manifest.version} is back in place: nothing changed.`, "err");
        } else {
          this.keepVersion(id, join(dest, "repo.old"), before);
          job.log(`${before.manifest.name} ${before.manifest.version} is kept: Roll back puts it back.`, "err");
        }
        throw e;
      }
      this.keepVersion(id, join(dest, "repo.old"), before);
      return res;
    }, grant, terminal);
  }

  // ---------------- versions: the checkouts before each update, for Roll back
  // <addon>/versions/<version>-<time>/repo + kept.json (the registry as it was)
  keepVersion(id, repo, before) {
    try {
      if (!existsSync(repo)) return;
      const v = before.manifest?.version || "0.0.0";
      const dir = join(this.addonDir(id), "versions", `${v}-${Date.now().toString(36)}`);
      mkdirSync(dir, { recursive: true });
      renameSync(repo, join(dir, "repo"));
      writeFileSync(join(dir, "kept.json"), JSON.stringify({ version: v, at: Date.now(), before }));
      for (const x of this.keptVersions(id).slice(KEEP_VERSIONS)) rmSync(join(this.addonDir(id), "versions", x.dir), { recursive: true, force: true });
    } catch { rmSync(repo, { recursive: true, force: true }); }
  }
  keptVersions(id) {
    const root = join(this.addonDir(id), "versions");
    let names = [];
    try { names = readdirSync(root); } catch { return []; }
    return names.map((n) => {
      try {
        const k = JSON.parse(readFileSync(join(root, n, "kept.json"), "utf8"));
        return existsSync(join(root, n, "repo")) ? { dir: n, version: k.version, at: k.at, commit: k.before?.commit || null } : null;
      } catch { return null; }
    }).filter(Boolean).sort((a, b) => b.at - a.at);
  }
  versionsView(id) {
    const rec = this.get(id);
    return { id, name: rec.manifest.name, current: rec.installed_version || rec.manifest.version, commit: rec.commit || null, hold: rec.hold || null,
             kept: this.keptVersions(id).map(({ dir, ...k }) => ({ ...k, key: dir })) };
  }

  // Back to a kept version (the newest, or `key`): its checkout and its registry
  // entry come back, its update (or install) script runs again, and the version
  // left is noted (hold) until the next update.
  rollback(id, key, { root: grant = null, terminal = null } = {}) {
    const rec = this.get(id);
    const kept = this.keptVersions(id);
    const pick = key ? kept.find((k) => k.dir === key || k.version === key) : kept[0];
    if (!pick) fail(`${rec.manifest.name} has no earlier version kept here (one is kept at each update from now on).`);
    return this.startJob(id, "rollback", `Rolling ${rec.manifest.name} back to ${pick.version}`, async (job) => {
      const dest = this.addonDir(id), from = join(dest, "versions", pick.dir);
      const k = JSON.parse(readFileSync(join(from, "kept.json"), "utf8"));
      const was = rec.installed_version || rec.manifest.version;
      const leaving = { manifest: rec.manifest, commit: rec.commit, updated: rec.updated, remote: rec.remote || null };
      job.phase = `Putting ${rec.manifest.name} ${pick.version} back`;
      rmSync(join(dest, "repo.old"), { recursive: true, force: true });
      if (existsSync(join(dest, "repo"))) renameSync(join(dest, "repo"), join(dest, "repo.old"));
      renameSync(join(from, "repo"), join(dest, "repo"));
      rmSync(from, { recursive: true, force: true });
      this.keepVersion(id, join(dest, "repo.old"), leaving);
      let m;
      try { m = loadManifest(join(dest, "repo", rec.source?.subdir || "")); } catch { m = k.before.manifest; }
      job.log(`${rec.manifest.name} ${was} -> ${m.version} (rolled back)`);
      let cur = this.patch(id, { manifest: m, commit: k.before.commit || null, updated: Date.now(), remote: null, hold: { version: was, at: Date.now() } });
      if (cur.installed) {
        const script = m.scripts.update || m.scripts.install;
        if (script) {
          job.phase = `Setting ${m.name} ${m.version} up again`; job.progress = 0.3;
          const r = await this.run(cur, script, { job, extra: { ADDON_UPDATE: "1", ADDON_ADOPT: "1", ADDON_ROLLBACK: "1", ...(m.requires.root ? this.rootEnv(grant) : {}) }, timeout: TIMEOUT.update });
          if (r.code !== 0) fail(`${m.name} ${m.version} is back in place, but its ${m.scripts.update ? "update" : "install"} script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
          cur = this.patch(id, { open_url: r.dir.open || cur.open_url });
        }
        cur = this.patch(id, { installed_version: m.version });
      }
      return { id, name: m.name, version: m.version, rolledBack: true };
    }, grant, terminal);
  }

  uninstall(id, keepData = true, { root: grant = null, terminal = null } = {}) {
    const rec = this.get(id), m = rec.manifest;
    const why = this.rootNeed(rec, "uninstall");
    if (why && !grant && !terminal) this.refuseRoot(rec, "uninstall", why);
    return this.startJob(id, "uninstall", `Uninstalling ${m.name}`, async (job) => {
      if (m.scripts.uninstall) {
        const r = await this.run(rec, m.scripts.uninstall, { job, extra: { ADDON_KEEP_DATA: keepData ? "1" : "0", ...this.rootEnv(grant) }, timeout: TIMEOUT.uninstall });
        if (r.code !== 0) fail(`the uninstall script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
      } else job.log(`${m.name} has no uninstall script; Burrow only forgets that it is installed.`);
      if (!keepData) rmSync(join(this.addonDir(id), "data"), { recursive: true, force: true });
      await this.share(id, false).catch(() => {});
      this.patch(id, { installed: false, installed_version: null, open_url: null, adopted: false });
      return { id, name: m.name, kept_data: !!keepData };
    }, grant, terminal);
  }

  remove(id, force = false) {
    const rec = this.get(id);
    if (rec.installed && !force) fail(`Uninstall ${rec.manifest.name} first.`);
    const all = this.load(); delete all[id]; this.save(all);
    rmSync(this.addonDir(id), { recursive: true, force: true });
    this.statusCache.delete(id); this.scanCache = null;
    return { ok: true, id };
  }

  action(id, actionId, { root: grant = null, terminal = null } = {}) {
    const rec = this.get(id);
    const a = rec.manifest.actions.find((x) => x.id === actionId);
    if (!a) fail(`${rec.manifest.name} has no action ${actionId}.`);
    if (!rec.installed) fail(`Install ${rec.manifest.name} first.`);
    const why = this.rootNeed(rec, "action", a.id);
    if (why && !grant && !terminal) this.refuseRoot(rec, "action", why, a.label);
    return this.startJob(id, "action", `${rec.manifest.name}: ${a.label}`, async (job) => {
      const r = await this.run(rec, a.script, { job, timeout: TIMEOUT.action, extra: this.rootEnv(grant) });
      if (r.code !== 0) fail(`${a.label} failed (exit ${r.code})`);
      return { id, action: a.id, open_url: r.dir.open, warnings: r.dir.warn };
    }, grant, terminal);
  }

  // Start it whatever it takes, and write down why when it won't (burrow/rescue.mjs).
  rescue(id) {
    const rec = this.get(id);
    if (!rec.installed) fail(`Install ${rec.manifest.name} first.`);
    return this.startJob(id, "rescue", `Starting ${rec.manifest.name}`, (job) => rescueAddon(this, this.get(id), job));
  }
  reports(id) { this.get(id); return rescueReports(this, id); }
  report(id, file) { this.get(id); const t = rescueReport(this, id, file); if (t == null) fail("No such report."); return t; }

  job(jid) { const j = this.jobs.get(jid); if (!j) fail("No such job."); return j; }

  // ---------------- the watchdog: an addon that stops on its own
  // Every minute, each installed addon with a status script and a start (or
  // restart) action is looked at. One that was running and now isn't, without
  // Burrow having stopped it, is marked rec.down: the dashboard asks whether to
  // start it again, or starts it straight away once the user said "always"
  // (rec.autoRestart). rec.watch keeps the last state across restarts of
  // Aegis, so an addon that died while Aegis was down is noticed too.
  startAction(rec) { return rec.manifest.actions.find((a) => a.id === "start") || rec.manifest.actions.find((a) => a.id === "restart") || null; }
  watch(every = 60e3) {
    clearInterval(this.watchTimer);
    const tick = () => this.watchOnce().catch((e) => this.log("addons: watchdog:", e.message));
    this.watchTimer = setInterval(tick, every);
    this.watchTimer.unref?.();
    return tick;
  }
  async watchOnce() {
    for (const rec of Object.values(this.load())) {
      if (!rec.installed || !rec.manifest.scripts.status || !this.startAction(rec)) continue;
      if ([...this.jobs.values()].some((j) => j.aid === rec.id && j.state === "running")) continue;
      const st = await this.status(rec, 0);
      const was = rec.watch?.state;
      if (st.state === "running") {
        if (was !== "running" || rec.down || rec.watch?.misses) this.patch(rec.id, { watch: { state: "running", at: Date.now() }, down: null });
        continue;
      }
      const ownDoing = (this.expectUntil.get(rec.id) || 0) > Date.now();
      // Down only after WATCH_MISSES checks in a row: on a loaded machine (a Pi 3 swapping)
      // one status script that ran past its timeout read as "stopped on its own", and the
      // watchdog "restarted" an app that was running all along, loading the machine further.
      if (was === "running" && !ownDoing && (st.state === "stopped" || st.state === "error")) {
        const misses = (rec.watch?.misses || 0) + 1;
        if (misses < WATCH_MISSES) { this.patch(rec.id, { watch: { state: "running", at: rec.watch?.at || Date.now(), misses } }); continue; }
      }
      if (was === "running" && !ownDoing && (st.state === "stopped" || st.state === "error")) {
        const down = { at: Date.now(), state: st.state, detail: st.detail || "", auto: !!rec.autoRestart };
        this.log(`addon ${rec.id}: stopped on its own (${st.state}${st.detail ? ": " + st.detail : ""})${rec.autoRestart ? "; starting it again" : "; asking whether to start it"}`);
        this.patch(rec.id, { watch: { state: st.state, at: Date.now() }, down });
        if (rec.autoRestart) {
          try { this.startDown(rec.id); } catch (e) { this.log(`addon ${rec.id}: couldn't start it again:`, e.message); }
        }
        this.onChange?.(rec.id);
      } else if (was !== st.state) this.patch(rec.id, { watch: { state: st.state, at: Date.now() } });
    }
  }
  // The answer to "start it back up?": start it (and maybe always do), or leave it off.
  answerDown(id, { start, always }, grant = null) {
    this.get(id);
    if (always !== undefined) this.patch(id, { autoRestart: !!always });
    if (!start) { this.patch(id, { down: null }); return null; }
    const job = this.startDown(id, grant);
    return job;
  }
  startDown(id, grant = null) {
    const rec = this.get(id);
    const a = this.startAction(rec);
    if (!a) fail(`${rec.manifest.name} has no start action.`);
    let job;
    try { job = this.action(id, a.id, { root: grant }); } catch (e) { if (grant) this.root.drop(grant.token); throw e; }
    this.patch(id, { down: rec.down ? { ...rec.down, starting: Date.now() } : null });
    return job;
  }
  setAutoRestart(id, on) { this.get(id); this.patch(id, { autoRestart: !!on }); return { id, autoRestart: !!on }; }
  // The addons that stopped on their own, from the registry alone (no status
  // scripts run): cheap enough for every page to poll.
  downList() {
    return Object.values(this.load()).filter((r) => r.installed && r.down).map((r) => ({
      id: r.id, name: r.manifest.name, down: r.down, autoRestart: !!r.autoRestart,
      busy: [...this.jobs.values()].some((j) => j.aid === r.id && j.state === "running"),
      logo: r.manifest.logo ? `/__gate/api/addons/${r.id}/image?v=${(r.commit || String(r.updated || 0)).slice(0, 12)}` : null,
    }));
  }

  // Is there newer code than what this addon was fetched at? (git sources)
  async checkUpdates(id) {
    const rec = this.get(id), src = rec.source, m = rec.manifest;
    const out = { id, name: m.name, source: src.display, checked: Date.now(), local: { commit: rec.commit, version: m.version } };
    if (src.kind === "archive") {
      // download it again: the same bytes mean nothing changed
      const tmp = mkdtempSync(join(this.dir, ".chk-"));
      try {
        const digest = await fetchSource(src, join(tmp, "x"));
        let version = "", card = null, root = null;
        try { const nm = loadManifest(join(tmp, "x", rec.subdir || "")); version = nm.version; card = nm.update_card; root = nm.requires.root; } catch { /* */ }
        out.up_to_date = digest === rec.commit;
        out.remote = { commit: digest, short: digest.slice(7, 14), version, subject: "a new archive", card, root };
        out.note = out.up_to_date ? "Checked by downloading the archive again." : "The archive at that link has changed.";
        this.patch(id, { remote: { checked: out.checked, up_to_date: out.up_to_date, commit: digest, version, subject: "a new archive", card, ...(root == null ? {} : { root }) } });
        return out;
      } finally { rmSync(tmp, { recursive: true, force: true }); }
    }
    if (src.kind !== "git") { out.up_to_date = null; out.note = "Added from a folder on this machine. Update copies the folder again."; return out; }
    const repo = join(this.addonDir(id), "repo");
    let r = await git(["fetch", "--quiet", "--depth", "40", "--filter=blob:none", "origin", src.ref || "HEAD"], { cwd: repo, timeout: 90 });
    if (r.code !== 0) fail(`Could not reach ${src.display}: ${r.err.trim().split("\n").pop() || "git fetch failed"}`);
    const remote = (await git(["rev-parse", "FETCH_HEAD"], { cwd: repo, timeout: 20 })).out.trim();
    const sub = (rec.subdir || "").replace(/^\/+|\/+$/g, "");
    let same = remote === rec.commit;
    if (!same && sub && rec.commit) {
      const a = await git(["rev-parse", `${remote}:${sub}`], { cwd: repo }), b = await git(["rev-parse", `${rec.commit}:${sub}`], { cwd: repo });
      if (a.code === 0 && b.code === 0 && a.out.trim() === b.out.trim()) { same = true; out.note = "The repository has newer commits, but none of them touch this addon."; }
    }
    out.up_to_date = same;
    const info = (line) => { const [h, ct, an, subj] = line.split("\t"); return { commit: h, short: h.slice(0, 7), date: Number(ct) || 0, author: an || "", subject: subj || "" }; };
    if (!same) {
      r = await git(["log", "--format=%H%x09%ct%x09%an%x09%s", "-n", "30", remote, ...(sub ? ["--", sub] : [])], { cwd: repo, timeout: 30 });
      const commits = [];
      for (const line of r.out.split("\n").filter(Boolean)) { const c = info(line); if (c.commit === rec.commit) break; commits.push(c); }
      out.commits = commits.slice(0, 20);
      out.remote = commits[0] || { commit: remote, short: remote.slice(0, 7) };
      const mj = await git(["show", `${remote}:${(sub ? sub + "/" : "") + MANIFEST}`], { cwd: repo, timeout: 60 });
      let nm = null;
      try { nm = mj.code === 0 ? JSON.parse(mj.out) : null; } catch { /* not JSON there */ }
      out.remote.version = String(nm?.version || "").slice(0, 30);
      // the new version's own update card (a bad one is left out, never in the way of the update)
      try { out.remote.card = cleanUpdateCard(nm?.update_card); } catch { out.remote.card = null; }
      // and whether it needs root (asked before the update runs)
      try { out.remote.root = nm ? rootReason(nm.requires?.root) : null; } catch { out.remote.root = null; }
    } else out.remote = { commit: remote, short: remote.slice(0, 7) };
    this.patch(id, { remote: { checked: out.checked, up_to_date: same, commit: out.remote.commit, version: out.remote.version || null, subject: out.remote.subject || null, count: same ? 0 : (out.commits || []).length, card: out.remote.card || null, ...(typeof out.remote.root === "string" ? { root: out.remote.root } : {}) } });
    return out;
  }

  // Check every installed addon fetched from a link (git or archive) whose last
  // check is older than maxAge, one at a time; a check already running is shared.
  checkAll(maxAge = 6 * 3600e3) {
    if (this.checking) return this.checking;
    this.checking = (async () => {
      for (const rec of Object.values(this.load())) {
        if (!rec.installed || !["git", "archive"].includes(rec.source?.kind)) continue;
        if (Date.now() - (rec.remote?.checked || 0) < maxAge) continue;
        if ([...this.jobs.values()].some((j) => j.aid === rec.id && j.state === "running")) continue;
        try { await this.checkUpdates(rec.id); } catch (e) { this.log(`addon ${rec.id}: update check failed:`, e.message); }
      }
    })().finally(() => { this.checking = null; });
    return this.checking;
  }

  // Installed addons whose source has something newer, as the last checks found.
  updates() {
    return Object.values(this.load()).filter((r) => r.installed && r.remote?.up_to_date === false).map((r) => ({
      id: r.id, name: r.manifest.name, version: r.installed_version || r.manifest.version, latest: r.remote.version || null,
      commit: r.remote.commit || null, from: r.commit || null, subject: r.remote.subject || null, count: r.remote.count || 0, checked: r.remote.checked,
      card: r.remote.card || r.manifest.update_card || null, root: this.rootNeed(r, "update") || null,
      logo: r.manifest.logo ? `/__gate/api/addons/${r.id}/image?v=${(r.commit || String(r.updated || 0)).slice(0, 12)}` : null,
    }));
  }

  // ---------------- ways in: an addon whose status names a port can get a Burrow address
  async share(id, on, access = "login") {
    const rec = this.get(id);
    const st = await this.status(rec, 0);
    if (!st.port) fail(`${rec.manifest.name} doesn't say which port it listens on.`);
    if (!this.tunnels) fail("Burrow's tunnels are not available.");
    const have = this.tunnels.list().find((t) => t.targetPort === st.port);
    if (on) return have || this.tunnels.create({ port: st.port, targetPort: st.port, targetHost: listenHost(st), name: rec.manifest.name, access });
    if (have) await this.tunnels.remove(have.port);
    return null;
  }

  image(id, rel) {
    const rec = this.get(id), root = this.rootOf(rec);
    rel = rel ? rel : rec.manifest.logo;
    const allowed = [rec.manifest.logo, ...rec.manifest.settings.map((s) => s.icon)].filter(Boolean);
    if (!rel || !allowed.includes(rel)) fail("No such image.");
    return { body: readFileSync(join(root, rel)), type: IMAGE_TYPES[extname(rel).toLowerCase()] };
  }

  // ---------------- what the UI shows
  async view(rec, withStatus = false) {
    const m = rec.manifest, v = (rec.commit || String(rec.updated || 0)).slice(0, 12);
    const out = {
      id: rec.id, name: m.name, version: m.version, description: m.description, author: m.author, license: m.license,
      homepage: m.homepage, links: m.links, platforms: m.platforms || PLATFORMS,
      logo: m.logo ? `/__gate/api/addons/${rec.id}/image?v=${v}` : null,
      source: rec.source?.display, commit: rec.commit, added: rec.added, updated: rec.updated,
      installed: !!rec.installed, installed_version: rec.installed_version || null, adopted: !!rec.adopted, open_url: rec.open_url || null,
      kept: rec.installed ? this.keptVersions(rec.id).map((k) => ({ version: k.version, at: k.at, key: k.dir })) : [], hold: rec.hold || null,
      detected: rec.detected || { found: false },
      settings: m.settings.map((st) => {
        const cur = (rec.settings || {})[st.key] ?? st.default;
        return { ...st, value: st.type === "password" ? (cur ? MASK : "") : cur, icon: st.icon ? `/__gate/api/addons/${rec.id}/image?path=${encodeURIComponent(st.icon)}&v=${v}` : undefined };
      }),
      actions: m.actions.map((a) => ({ id: a.id, label: a.label, confirm: a.confirm, root: !!a.root })),
      // what needs root, from the manifest alone (GET …/root asks sudo)
      root: m.requires?.root || m.actions.some((a) => a.root)
        ? { reason: m.requires?.root || "", install: !!this.rootNeed(rec, "install"), update: !!this.rootNeed(rec, "update"), uninstall: !!this.rootNeed(rec, "uninstall"),
            actions: m.actions.filter((a) => a.root).map((a) => a.id), passwordless: this.root.checked?.value?.passwordless ?? null } : null,
      has: Object.fromEntries(SCRIPTS.map((k) => [k, k in m.scripts])),
      problems: checkRequirements(m, this.version), remote: rec.remote || null,
      down: rec.down || null, autoRestart: !!rec.autoRestart, restartable: !!this.startAction(rec) && !!m.scripts.status,
      busy: [...this.jobs.values()].find((j) => j.aid === rec.id && j.state === "running")?.view(1e9) || null,
    };
    out.update_pending = !!(out.installed && out.installed_version && out.installed_version !== m.version);
    if (withStatus) {
      const st = await this.status(rec);
      out.status = st;
      if (st.url) out.open_url = st.url;
      if (st.name && out.installed) out.name = st.name;
      if (st.port && this.tunnels) {
        const t = this.tunnels.list().find((x) => x.targetPort === st.port);
        out.ways = { port: st.port, local: `http://${listenHost(st)}:${st.port}/`, burrow: t ? { port: t.port, url: t.url, access: t.access, enabled: t.enabled } : null };
      }
    }
    return out;
  }

  async list() {
    const recs = Object.values(this.load()).sort((a, b) => (!!b.installed - !!a.installed) || a.manifest.name.localeCompare(b.manifest.name));
    return Promise.all(recs.map((r) => this.view(r, true)));
  }

  // ---------------- the smart scan: addons already on this machine
  async scan(maxAge = 60000) {
    if (this.scanCache && Date.now() - this.scanCache.scanned < maxAge) return this.scanCache;
    const mine = realpathSync(this.dir) + sep;
    const reg = this.load();
    const byId = new Map(), broken = [];
    for (const d of findManifests()) {
      let real;
      try { real = realpathSync(d) + sep; } catch { continue; }
      if (real.startsWith(mine)) continue;                 // our own checkouts
      try {
        const m = loadManifest(d);
        if (SELF.includes(m.id)) continue;                 // Aegis × Burrow itself, and what it grew from
        (byId.get(m.id) || byId.set(m.id, []).get(m.id)).push([d, m]);
      }
      catch (e) { broken.push({ path: d, error: e.message }); }
    }
    // an addon that replaces older ones (renamed, merged) hides them
    const gone = new Set([...byId.values()].flat().flatMap(([, m]) => m.replaces || []));
    for (const r of Object.values(reg)) for (const x of r.manifest?.replaces || []) gone.add(x);
    for (const id of [...byId.keys()]) if (gone.has(id)) byId.delete(id);
    const one = async (id, places) => {
      places.sort((a, b) => vcmp(versionTuple(b[1].version), versionTuple(a[1].version)) || (existsSync(join(b[0], ".git")) - existsSync(join(a[0], ".git"))));
      const [d, m] = places[0];
      const rec = reg[id];
      let probe;
      if (rec?.installed) { const st = await this.status(rec); probe = { found: true, state: st.state, version: rec.installed_version, name: st.name, detail: st.detail }; }
      else probe = await this.probe(d, m);
      let logo = null;
      try { if (m.logo?.endsWith(".svg") && statSync(join(d, m.logo)).size <= 65536) logo = "data:image/svg+xml;base64," + readFileSync(join(d, m.logo)).toString("base64"); } catch { /* */ }
      return { id, name: probe.name || m.name, version: m.version, description: m.description.slice(0, 300), logo,
               platforms: m.platforms, compatible: m.platforms.includes(HOST), problems: checkRequirements(m, this.version),
               registered: !!rec, installed: !!rec?.installed, found: !!probe.found, installed_version: probe.version || null,
               state: probe.state || null, detail: probe.detail || "", source: await gitSource(d), locations: places.map((p) => p[0]) };
    };
    const addons = (await Promise.all([...byId].map(([id, p]) => one(id, p))))
      .sort((a, b) => (!a.compatible - !b.compatible) || (a.registered - b.registered) || (!a.found - !b.found) || a.name.localeCompare(b.name));
    this.scanCache = { scanned: Date.now(), addons, broken: broken.slice(0, 20) };
    return this.scanCache;
  }

  async probe(root, m) {
    const rec = { id: m.id, manifest: m, settings: {} };
    const scratch = mkdtempSync(join(this.dir, ".scan-"));
    const at = { root, data: scratch, extra: { ADDON_SCAN: "1" } };
    try {
      const det = await this.detect(rec, at);
      const out = { found: det.found, version: det.version, detail: det.detail, state: null };
      if (det.found && m.scripts.status) {
        const r = await this.run(rec, m.scripts.status, { timeout: TIMEOUT.status, ...at });
        const i = lastJson(r.lines);
        out.state = String(i.state || "").slice(0, 20) || null;
        if (typeof i.name === "string") out.name = i.name.slice(0, 60);
      }
      return out;
    } catch { return { found: false, state: null }; }
    finally { rmSync(scratch, { recursive: true, force: true }); }
  }
}

// Folders to look in, and folders never worth entering.
const SKIP = new Set(["node_modules", "__pycache__", ".git", ".cache", ".npm", ".nvm", ".cargo", ".rustup", "snap", "venv", ".venv",
                      "site-packages", "go", ".gradle", ".m2", ".docker", "Downloads", "builds", "logs", "proc", "sys", "dev"]);
const HIDDEN_OK = new Set([".local", ".selkies-forge", ".config", ".share"]);
function findManifests({ budget = 25000, ms = 4000 } = {}) {
  const home = homedir();
  const roots = [[home, 4], ["/opt", 3], ["/srv", 3]];
  const cfg = process.env.XDG_CONFIG_HOME || join(home, ".config");
  try {
    for (const app of readdirSync(cfg)) {
      try { const d = JSON.parse(readFileSync(join(cfg, app, `${app}.json`), "utf8")); if (typeof d.code === "string") roots.push([d.code, 1]); } catch { /* */ }
    }
  } catch { /* */ }
  const found = [], seen = new Set(), t0 = Date.now();
  for (const [root, depth] of roots) {
    let start;
    try { start = realpathSync(root); } catch { continue; }
    const stack = [[start, 0]];
    while (stack.length && budget > 0 && Date.now() - t0 < ms) {
      const [d, lvl] = stack.pop();
      if (seen.has(d)) continue;
      seen.add(d); budget--;
      let ents;
      try { ents = readdirSync(d, { withFileTypes: true }); } catch { continue; }
      if (ents.some((e) => e.name === MANIFEST && e.isFile())) found.push(d);
      if (lvl >= depth) continue;
      for (const e of ents) {
        if (!e.isDirectory() || SKIP.has(e.name) || (e.name.startsWith(".") && !HIDDEN_OK.has(e.name))) continue;
        stack.push([join(d, e.name), lvl + 1]);
      }
    }
  }
  return found;
}

// A link a host can fetch (and later update) for a checkout at path, or the folder itself.
async function gitSource(path) {
  const top = await git(["rev-parse", "--show-toplevel"], { cwd: path, timeout: 10 });
  if (top.code === 0) {
    const o = await git(["remote", "get-url", "origin"], { cwd: path, timeout: 10 });
    const u = o.out.trim().replace(/\.git$/, "");
    if (o.code === 0 && /^https:\/\/\S+$/.test(u)) {
      const sub = relative(top.out.trim(), path);
      if (!sub) return u;
      const br = (await git(["rev-parse", "--abbrev-ref", "HEAD"], { cwd: path, timeout: 10 })).out.trim() || "main";
      return /^https:\/\/(github|gitlab)\.com\//.test(u) ? `${u}/tree/${br}/${sub}` : `${u}#${sub}`;
    }
  }
  return path;
}
