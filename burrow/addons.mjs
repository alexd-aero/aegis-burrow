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
// Scripts talk back with lines on stdout: "::progress N text", "::phase text",
// "::open URL", "::warn text"; status (and detect) end with one JSON line.

import { spawn, execFile } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, arch as osArch, platform as osPlatform } from "node:os";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { randomBytes } from "node:crypto";
import { ArchiveError, download, unpack } from "./archive.mjs";

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
const TIMEOUT = { detect: 20, status: 15, install: 3600, update: 3600, uninstall: 900, action: 900 };
const ARCH_ALIASES = { amd64: "x86_64", x64: "x86_64", arm64: "aarch64", armhf: "armv7l", arm: "armv7l" };
const MASK = "••••••••";

export class AddonError extends Error {}
const fail = (msg) => { throw new AddonError(msg); };

// ------------------------------------------------------------------ sources
// GitHub and Codeberg: OWNER/REPO/tree|blob/REF[/path]
const HOSTED_TREE = /^(https:\/\/(?:github\.com|codeberg\.org)\/[^/\s]+\/[^/\s#]+?)(?:\.git)?\/(?:tree|blob|src\/branch)\/([^/\s#]+)(?:\/([^#\s]*?))?\/?$/;
// GitLab, gitlab.com or self-hosted, with subgroups: GROUP/SUB/.../REPO/-/tree|blob/REF[/path]
const GITLAB_TREE = /^(https:\/\/[^/\s]+\/[^\s#]+?)(?:\.git)?\/-\/(?:tree|blob)\/([^/\s#]+)(?:\/([^#\s]*?))?\/?$/;
// a download: .zip, .tar.gz, .tgz (GitHub's and GitLab's archive links included)
const ARCHIVE = /^https?:\/\/[^\s#]+?\.(zip|tar\.gz|tgz)(?:\?[^\s#]*)?$/i;

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
  if (!/^(https?:\/\/[^\s/]+\/\S+|ssh:\/\/\S+|git@[^\s:]+:\S+)$/.test(url)) fail("That does not look like a git repository link.");
  sub = sub.replace(/^\/+|\/+$/g, "");
  if (sub && (sub.split("/").includes("..") || !/^[A-Za-z0-9._/-]+$/.test(sub))) fail("The folder part of the link is not valid.");
  return { kind: "git", url, ref, subdir: sub, display: raw };
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
  if (source.kind === "local") {
    cpSync(source.path, dest, { recursive: true, verbatimSymlinks: true,
      filter: (p) => !/(^|\/)(\.git|node_modules|__pycache__)$/.test(p) });
    return null;
  }
  const base = ["clone", "--depth", "1", "--quiet", ...(source.ref ? ["--branch", source.ref] : [])];
  let r = { code: 1, err: "" };
  if (source.subdir) {
    r = await git([...base, "--filter=blob:none", "--sparse", source.url, dest]);
    if (r.code === 0) {
      r = await git(["sparse-checkout", "set", "--no-cone", `/${source.subdir}/`], { cwd: dest });
      if (r.code !== 0) rmSync(dest, { recursive: true, force: true });
    }
  }
  if (r.code !== 0) r = await git([...base, source.url, dest]);
  if (r.code !== 0) {
    let msg = r.err.trim().split("\n").pop() || "git clone failed";
    if (/could not read Username|Authentication failed|not found/i.test(r.err)) msg = "the repository was not found, or it is private";
    if (/ENOENT/.test(r.err)) msg = "git is not installed on this machine";
    fail(`Could not fetch ${source.display}: ${msg}`);
  }
  const h = await git(["rev-parse", "HEAD"], { cwd: dest, timeout: 20 });
  return h.code === 0 ? h.out.trim().slice(0, 40) : null;
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
    m.actions.push({ id: a.id, label: text(a, "label", 24, true), script: inside(root, a.script, `actions.${a.id}.script`), confirm: text(a, "confirm", 200) });
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
             started: this.started, finished: this.finished, result: this.result, error: this.error,
             next: this.base + this.lines.length, lines: this.lines.slice(from) };
  }
  cancel() { if (this.state !== "running") return; this.cancelled = true; for (const p of this.procs) { try { process.kill(-p.pid, "SIGTERM"); } catch { /* */ } } }
}

// ------------------------------------------------------------------ the host
export class Addons {
  // dir:      where checkouts and data live (AEGIS_HOME/addons)
  // registry: the JSON file that remembers them (DATA/addons.json)
  // env:      () => {ADDON_HOST_URL, ADDON_BIND, BURROW_SOCKET, …}: host values for scripts
  constructor({ dir, registry, version, env, log, tunnels, onChange }) {
    Object.assign(this, { dir, registryFile: registry, version, hostEnv: env || (() => ({})), log: log || console.log, tunnels, onChange });
    this.statusCache = new Map();
    this.jobs = new Map();
    this.scanCache = null;
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
    const e = { ...process.env, ADDON_SPEC: String(SPEC), ADDON_ID: m.id, ADDON_NAME: m.name, ADDON_VERSION: m.version,
                ADDON_DIR: root, ADDON_DATA: data, ADDON_ADOPT: "0", ADDON_UPDATE: "0", ADDON_ARCH: machine(),
                ADDON_HOST: HOST, ADDON_HOST_VERSION: this.version, ...this.hostEnv() };
    for (const st of m.settings) {
      let v = (rec.settings || {})[st.key] ?? st.default;
      v = v == null ? "" : st.type === "bool" ? (v ? "1" : "0") : String(v);
      e["ADDON_SETTING_" + st.key] = v;
    }
    Object.assign(e, extra);
    // the older names, for scripts written for Selkies Forge first
    for (const k of Object.keys(e)) if (k.startsWith("ADDON_") && !k.startsWith("ADDON_HOST")) e["FORGE_" + k] = e[k];
    if (e.ADDON_BIND) e.FORGE_BIND = e.ADDON_BIND;
    return e;
  }

  run(rec, rel, { job, extra, timeout = 600, root, data } = {}) {
    root = root || this.rootOf(rec);
    data = data || this.dataDir(rec);
    return new Promise((done) => {
      const p = spawn("bash", [join(root, rel)], { cwd: root, env: this.env(rec, root, data, extra), detached: true, stdio: ["ignore", "pipe", "pipe"] });
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

  startJob(aid, kind, label, work) {
    for (const j of this.jobs.values()) if (j.aid === aid && j.state === "running") fail(`${label.split(" ").pop()} is busy: ${j.label}.`);
    const job = new Job(aid, kind, label);
    this.jobs.set(job.id, job);
    for (const [id, j] of this.jobs) if (j.state !== "running" && Date.now() - j.started > 3600e3) this.jobs.delete(id);
    Promise.resolve().then(() => work(job)).then((res) => {
      Object.assign(job, { state: "done", result: res || null, progress: 1, phase: "done" });
    }).catch((e) => {
      Object.assign(job, { state: job.cancelled ? "cancelled" : "error", error: e.message });
      job.log(e.message, "err");
    }).finally(() => { job.finished = Date.now(); this.statusCache.delete(aid); this.scanCache = null; this.log(`addon ${aid}: ${kind} ${job.state}`); this.onChange?.(aid); });
    return job.view();
  }

  install(id, settings) {
    const rec0 = this.get(id), m = rec0.manifest;
    const problems = checkRequirements(m, this.version);
    if (problems.length) fail(`${m.name} ${problems.join("; ")}.`);
    const rec = this.patch(id, { settings: this.cleanSettings(rec0, settings || {}) });
    return this.startJob(id, "install", `Installing ${m.name}`, async (job) => {
      const found = await this.detect(rec);
      const adopt = found.found && !rec.installed;
      job.phase = adopt ? `Linking the ${m.name} already on this machine` : `Installing ${m.name}`;
      if (adopt) job.log(`${m.name} is already on this machine${found.detail ? ` (${found.detail})` : ""}; linking it.`);
      const r = await this.run(rec, m.scripts.install, { job, extra: { ADDON_ADOPT: adopt ? "1" : "0" }, timeout: TIMEOUT.install });
      if (r.code !== 0) fail(`the install script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
      const done = this.patch(id, { installed: true, installed_version: m.version, installed_at: Date.now(), adopted: !!adopt,
                                    open_url: r.dir.open || found.url || rec.open_url || null, detected: found });
      return { id, name: m.name, open_url: done.open_url, adopted: !!adopt, warnings: r.dir.warn };
    });
  }

  update(id) {
    const rec = this.get(id);
    return this.startJob(id, "update", `Updating ${rec.manifest.name}`, async (job) => {
      job.phase = `Fetching ${rec.manifest.name}`;
      const tmp = mkdtempSync(join(this.dir, ".upd-"));
      let m, commit;
      try {
        commit = await fetchSource(rec.source, join(tmp, "repo"));
        m = loadManifest(join(tmp, "repo", rec.source.subdir || ""));
        if (m.id !== id) fail(`the repository now holds a different addon (${m.id})`);
        const dest = this.addonDir(id);
        rmSync(join(dest, "repo.old"), { recursive: true, force: true });
        if (existsSync(join(dest, "repo"))) renameSync(join(dest, "repo"), join(dest, "repo.old"));
        renameSync(join(tmp, "repo"), join(dest, "repo"));
        rmSync(join(dest, "repo.old"), { recursive: true, force: true });
      } finally { rmSync(tmp, { recursive: true, force: true }); }
      job.log(`${m.name} ${rec.manifest.version} -> ${m.version}${commit ? ` (${commit.slice(0, 10)})` : ""}`);
      let cur = this.patch(id, { manifest: m, commit, updated: Date.now(), remote: null });
      const res = { id, name: m.name, version: m.version, ran: null };
      if (cur.installed) {
        const script = m.scripts.update || m.scripts.install;
        res.ran = m.scripts.update ? "update" : "install";
        job.phase = `Updating ${m.name}`; job.progress = 0.2;
        const r = await this.run(cur, script, { job, extra: { ADDON_UPDATE: "1", ADDON_ADOPT: "1" }, timeout: TIMEOUT.update });
        if (r.code !== 0) fail(`the update script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
        cur = this.patch(id, { installed_version: m.version, open_url: r.dir.open || cur.open_url });
        res.open_url = cur.open_url;
      }
      return res;
    });
  }

  uninstall(id, keepData = true) {
    const rec = this.get(id), m = rec.manifest;
    return this.startJob(id, "uninstall", `Uninstalling ${m.name}`, async (job) => {
      if (m.scripts.uninstall) {
        const r = await this.run(rec, m.scripts.uninstall, { job, extra: { ADDON_KEEP_DATA: keepData ? "1" : "0" }, timeout: TIMEOUT.uninstall });
        if (r.code !== 0) fail(`the uninstall script failed (exit ${r.code}): ${(r.lines.filter((l) => l.trim()).pop() || "no output").slice(0, 300)}`);
      } else job.log(`${m.name} has no uninstall script; Burrow only forgets that it is installed.`);
      if (!keepData) rmSync(join(this.addonDir(id), "data"), { recursive: true, force: true });
      await this.share(id, false).catch(() => {});
      this.patch(id, { installed: false, installed_version: null, open_url: null, adopted: false });
      return { id, name: m.name, kept_data: !!keepData };
    });
  }

  remove(id, force = false) {
    const rec = this.get(id);
    if (rec.installed && !force) fail(`Uninstall ${rec.manifest.name} first.`);
    const all = this.load(); delete all[id]; this.save(all);
    rmSync(this.addonDir(id), { recursive: true, force: true });
    this.statusCache.delete(id); this.scanCache = null;
    return { ok: true, id };
  }

  action(id, actionId) {
    const rec = this.get(id);
    const a = rec.manifest.actions.find((x) => x.id === actionId);
    if (!a) fail(`${rec.manifest.name} has no action ${actionId}.`);
    if (!rec.installed) fail(`Install ${rec.manifest.name} first.`);
    return this.startJob(id, "action", `${rec.manifest.name}: ${a.label}`, async (job) => {
      const r = await this.run(rec, a.script, { job, timeout: TIMEOUT.action });
      if (r.code !== 0) fail(`${a.label} failed (exit ${r.code})`);
      return { id, action: a.id, open_url: r.dir.open, warnings: r.dir.warn };
    });
  }

  job(jid) { const j = this.jobs.get(jid); if (!j) fail("No such job."); return j; }

  // Is there newer code than what this addon was fetched at? (git sources)
  async checkUpdates(id) {
    const rec = this.get(id), src = rec.source, m = rec.manifest;
    const out = { id, name: m.name, source: src.display, checked: Date.now(), local: { commit: rec.commit, version: m.version } };
    if (src.kind === "archive") {
      // download it again: the same bytes mean nothing changed
      const tmp = mkdtempSync(join(this.dir, ".chk-"));
      try {
        const digest = await fetchSource(src, join(tmp, "x"));
        let version = "";
        try { version = loadManifest(join(tmp, "x", rec.subdir || "")).version; } catch { /* */ }
        out.up_to_date = digest === rec.commit;
        out.remote = { commit: digest, short: digest.slice(7, 14), version, subject: "a new archive" };
        out.note = out.up_to_date ? "Checked by downloading the archive again." : "The archive at that link has changed.";
        this.patch(id, { remote: { checked: out.checked, up_to_date: out.up_to_date, commit: digest, version, subject: "a new archive" } });
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
      try { out.remote.version = mj.code === 0 ? String(JSON.parse(mj.out).version || "").slice(0, 30) : ""; } catch { out.remote.version = ""; }
    } else out.remote = { commit: remote, short: remote.slice(0, 7) };
    this.patch(id, { remote: { checked: out.checked, up_to_date: same, commit: out.remote.commit, version: out.remote.version || null, subject: out.remote.subject || null, count: same ? 0 : (out.commits || []).length } });
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
      detected: rec.detected || { found: false },
      settings: m.settings.map((st) => {
        const cur = (rec.settings || {})[st.key] ?? st.default;
        return { ...st, value: st.type === "password" ? (cur ? MASK : "") : cur, icon: st.icon ? `/__gate/api/addons/${rec.id}/image?path=${encodeURIComponent(st.icon)}&v=${v}` : undefined };
      }),
      actions: m.actions.map((a) => ({ id: a.id, label: a.label, confirm: a.confirm })),
      has: Object.fromEntries(SCRIPTS.map((k) => [k, k in m.scripts])),
      problems: checkRequirements(m, this.version), remote: rec.remote || null,
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
