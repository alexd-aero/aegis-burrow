// Updates: Aegis × Burrow keeps itself current, and shows what changed.
//
//   check()     asks GitHub for main's package.json; a higher version there
//               means an update. Every 30 minutes, when a page opens (fresh(),
//               at most every two minutes), and when someone asks.
//   apply()     downloads main as a .tar.gz (burrow/archive.mjs: size caps, no
//               escaping paths), checks it is a whole Aegis × Burrow of that
//               version, swaps it in for app/ (the old one stays as app.prev),
//               and exits. The service manager starts the new code: systemd's
//               Restart=always, or `aegis start` for a plain background process.
//               Login, domain, tunnels and addons live in data/ and are kept.
//   auto        settings.updates.auto: apply by itself when a check finds one
//               (never a version held back: settings.updates.hold).
//   versions    the versions before are kept whole in AEGIS_HOME/versions/<v>/
//               (the newest KEEP of them), so going back is two renames and works
//               with no network; any older release comes from GitHub by commit.
//   rollback()  back to a kept version, or any release from GitHub (install(v));
//               the version left behind is held back, so auto-update doesn't
//               bring it straight back. bin/aegis rollback does the same with
//               the gate down.
//   boot guard  a new version is "on trial" (data/boot.json) until it has run
//               for a minute; aegis/server.mjs puts the version before back by
//               itself when it doesn't load or keeps dying (see there).
//   changelog() the newest commits of Aegis × Burrow, Selkies Forge and the
//               Weft Architecture, for Settings → Updates (cached for an hour).
//
// AEGIS_REPO (owner/name) points it at another copy, e.g. a fork, and
// AEGIS_UPDATE_MIRROR (a base URL serving /<repo>/main/package.json and
// /<repo>/tar.gz/refs/heads/main, like GitHub's) at a mirror or a test server.

import { chmodSync, cpSync, existsSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { APP, HOME, DATA, CONFIG_DIR, VERSION, readJson } from "./config.mjs";
import { download, unpack } from "../burrow/archive.mjs";
import { versionTuple } from "../burrow/addons.mjs";

export const REPOS = {
  "aegis-burrow": { name: "Aegis × Burrow", repo: process.env.AEGIS_REPO || "alexd-aero/aegis-burrow", logo: "/__gate/logos/aegis-burrow.svg" },
  "selkies-forge": { name: "Selkies Forge", repo: "adatskov-wcpss/animated-fiesta", logo: "/__gate/logos/forge.svg" },
  weft: { name: "Weft Architecture", repo: "alexd-aero/weft", logo: "/__gate/logos/weft.svg" },
  "burrow-pages": { name: "Burrow Pages", repo: "alexd-aero/burrow-pages", logo: "/__gate/logos/burrow-pages.svg" },
};
const OWN = REPOS["aegis-burrow"].repo;
const UA = `aegis-burrow/${VERSION} (+https://github.com/${OWN})`;
const MIRROR = process.env.AEGIS_UPDATE_MIRROR?.replace(/\/$/, "");
const RAW = MIRROR || "https://raw.githubusercontent.com", CODELOAD = MIRROR || "https://codeload.github.com";
const CHECK_EVERY = 30 * 60 * 1000;      // in the background; a page that opens checks sooner (fresh())
const FRESH = 2 * 60 * 1000;             // a check younger than this is good enough for a page
const LOG_TTL = 3600 * 1000;
export const VERSIONS = join(HOME, "versions");
export const BOOT = join(DATA, "boot.json");
const KEEP = 4;                          // earlier versions kept whole (~2 MB each)
const TRIAL_MS = 60 * 1000;              // a new version that runs this long is fine
const V_RE = /^\d+\.\d+\.\d+$/;
const versionOf = (dir) => { try { return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version || null; } catch { return null; } };
export const readBoot = () => readJson(BOOT, null);
export function writeBoot(b) { try { mkdirSync(DATA, { recursive: true }); writeFileSync(BOOT + ".tmp", JSON.stringify(b, null, 1)); renameSync(BOOT + ".tmp", BOOT); } catch { /* best effort */ } }

// Every module parses with this Node.js: a download that was cut short or
// mangled is refused before it replaces anything.
// Each .mjs of a download parses (`node --check`), else nothing changes. A file the
// same as the running one's (`same`, the app in use) needs no check: it runs already.
// A check that ran out of time is tried once more with longer; still out of time, it
// is let through (logged): the boot guard (server.mjs) rolls back a version that
// doesn't start. On a swapping Pi 3 ~40 Node launches took longer than 20 s each,
// and an unchanged gate.mjs was refused as "doesn't parse".
export function syntaxCheck(dir, { same = APP, log = () => {} } = {}) {
  const files = [];
  const walk = (d, depth = 0) => {
    let list = [];
    try { list = readdirSync(join(dir, d), { withFileTypes: true }); } catch { return; }
    for (const e of list) {
      const rel = d ? `${d}/${e.name}` : e.name;
      if (e.isDirectory()) { if (depth < 4 && !/^(node_modules|vendor|test|client)$/.test(e.name)) walk(rel, depth + 1); }
      else if (/\.mjs$/.test(e.name)) files.push(rel);
    }
  };
  for (const d of ["aegis", "burrow", "bin"]) walk(d);
  let checked = 0;
  for (const f of files) {
    if (same) { try { if (readFileSync(join(dir, f)).equals(readFileSync(join(same, f)))) continue; } catch { /* new or unreadable: check it */ } }
    let r = spawnSync(process.execPath, ["--check", join(dir, f)], { encoding: "utf8", timeout: 20000 });
    if (r.error?.code === "ETIMEDOUT" || r.signal) r = spawnSync(process.execPath, ["--check", join(dir, f)], { encoding: "utf8", timeout: 90000 });
    if (r.error?.code === "ETIMEDOUT" || r.signal) { log(`update: couldn't check ${f} in time (a busy machine); the boot guard covers it`); continue; }
    if (r.status !== 0) throw new Error(`${f} in the download doesn't parse (${(r.stderr || "").split("\n").find((l) => /Error/.test(l)) || "syntax error"}); nothing was changed.`);
    checked++;
  }
  return checked;
}

const newer = (a, b) => { const x = versionTuple(a), y = versionTuple(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i]; return false; };

async function getJson(url, ms = 15000) {
  const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(ms) });
  if (r.status === 403 || r.status === 429) throw new Error("GitHub is rate-limiting this machine; try again in a while.");
  if (!r.ok) throw new Error(`GitHub answered HTTP ${r.status}`);
  return r.json();
}

// "2.3.0: no setup token, …" -> {version: "2.3.0", title: "no setup token, …"}
export function entry(c) {
  const msg = String(c.commit?.message || "");
  const [subject, ...rest] = msg.split("\n");
  const m = /^v?(\d+\.\d+\.\d+)\s*[:–-]\s*(.*)$/.exec(subject.trim());
  const body = rest.filter((l) => !/^\s*(co-authored-by|signed-off-by):/i.test(l)).join("\n").trim();
  return { sha: c.sha, short: String(c.sha || "").slice(0, 7), version: m ? m[1] : null, title: m ? m[2] : subject.trim(),
           body: body.slice(0, 1500), date: Date.parse(c.commit?.committer?.date || c.commit?.author?.date || "") || null,
           url: c.html_url || null };
}

export class Updater {
  // exit: stop cleanly (tunnels, serveo) and leave; the service manager restarts us
  constructor({ settings, log, exit }) {
    this.settings = settings;
    this.exit = exit || (() => process.exit(0));
    this.log = log || console.log;
    this.state = { current: VERSION, latest: null, available: false, checked: null, error: null, title: null, entries: [] };
    this.job = null;                         // {state: running|done|error, phase, error, at}
    this.logs = new Map();                   // id -> {at, entries, error}
    this.timer = setTimeout(() => this.tick(), 20 * 1000);
    this.timer.unref?.();
    this.adoptPrev();
  }

  // ---------------------------------------------------------------- versions
  // The old app.prev (one version back, before 2.33) joins the kept versions.
  adoptPrev() {
    const prev = APP + ".prev";
    try {
      if (!existsSync(prev)) return;
      const v = versionOf(prev);
      mkdirSync(VERSIONS, { recursive: true });
      if (v && V_RE.test(v) && v !== VERSION && !existsSync(join(VERSIONS, v))) { renameSync(prev, join(VERSIONS, v)); this.stamp(v, "kept from before"); }
      else rmSync(prev, { recursive: true, force: true });
      this.prune();
    } catch (e) { this.log("update: couldn't keep", prev, e.message); }
  }
  stamp(v, why) { try { writeFileSync(join(VERSIONS, v, ".kept.json"), JSON.stringify({ version: v, at: Date.now(), why })); } catch { /* a nicety */ } }
  kept() {
    let names = [];
    try { names = readdirSync(VERSIONS); } catch { return []; }
    return names.filter((n) => !n.startsWith(".")).map((n) => {
      const dir = join(VERSIONS, n), v = versionOf(dir);
      const meta = readJson(join(dir, ".kept.json"), {}) || {};
      let at = meta.at; if (!at) { try { at = statSync(dir).mtimeMs; } catch { at = 0; } }
      return v ? { version: v, dir: n, at, broken: n.endsWith("-broken"), why: meta.why || null, whole: existsSync(join(dir, "aegis", "server.mjs")) } : null;
    }).filter(Boolean).sort((a, b) => b.at - a.at);
  }
  // the newest KEEP kept (a broken one counts too, and goes first)
  prune() {
    const list = this.kept();
    const ok = list.filter((x) => !x.broken), bad = list.filter((x) => x.broken);
    for (const x of [...ok.slice(KEEP), ...bad.slice(2)]) rmSync(join(VERSIONS, x.dir), { recursive: true, force: true });
  }

  // what you can go back (or forward) to: kept here, or a release on GitHub
  async versions() {
    const kept = this.kept();
    let releases = [], error = null;
    try {
      const log = await this.changelog("aegis-burrow");
      const seen = new Set();
      for (const e of log.entries) {
        if (!e.version || e.version === VERSION || seen.has(e.version)) continue;
        seen.add(e.version);
        releases.push({ version: e.version, title: e.title, date: e.date, sha: e.sha, short: e.short, url: e.url, newer: newer(e.version, VERSION),
                        kept: kept.some((k) => k.version === e.version && !k.broken) });
      }
    } catch (err) { error = err.message; }
    return { current: VERSION, hold: this.hold, boot: this.bootView(), kept: kept.map(({ dir, ...k }) => k), releases: releases.slice(0, 25), error, job: this.job, scope: this.scope() };
  }

  get hold() { return (this.settings.get("updates") || {}).hold || null; }
  setHold(v) { this.settings.set({ updates: { ...(this.settings.get("updates") || {}), hold: v && V_RE.test(v) ? { version: v, at: Date.now() } : null } }); }
  held(v) { const h = this.hold; return !!h && !newer(v, h.version); }

  bootView() {
    const b = readBoot();
    return b ? { state: b.state, from: b.from, to: b.to, at: b.at, why: b.why || null, starts: b.starts || 0 } : null;
  }
  // A new version is on trial until it has run for a minute (aegis/server.mjs
  // counts its starts). Called once the gate listens.
  confirmBoot() {
    const b = readBoot();
    if (!b) return;
    // the launcher went back by itself: hold the version that failed, and say so
    if (b.state === "rolled-back" && !b.noted) {
      if (b.failed) this.setHold(b.failed);
      writeBoot({ ...b, noted: Date.now() });
      this.onRolledBack?.(b);
      return;
    }
    if (b.state !== "trial" || b.to !== VERSION) return;
    setTimeout(() => { const c = readBoot(); if (c && c.state === "trial" && c.to === VERSION) writeBoot({ ...c, state: "ok", okAt: Date.now() }); }, TRIAL_MS).unref?.();
  }

  get auto() { return !!(this.settings.get("updates") || {}).auto; }
  setAuto(on) { this.settings.set({ updates: { ...(this.settings.get("updates") || {}), auto: !!on } }); }

  // how Aegis is run (aegis.json): user | system | background | manual
  scope() {
    const d = readJson(join(CONFIG_DIR, "aegis.json"), {}) || {};
    return d.home && d.home !== HOME ? "manual" : (d.service?.scope || "background");
  }

  async tick() {
    try {
      await this.check();
      if (this.state.available && this.auto && !this.job && !this.held(this.state.latest) && process.env.AEGIS_STANDBY !== "1") { this.log("update: applying", this.state.latest, "by itself (auto-update is on)"); await this.apply(); }
    } catch { /* noted in state */ }
    this.timer = setTimeout(() => this.tick(), CHECK_EVERY);
    this.timer.unref?.();
  }

  // A check no older than FRESH: what a page asks for when it opens, so a
  // new version shows up right away. Concurrent callers share one request.
  fresh() {
    if (this.state.checked && Date.now() - this.state.checked < FRESH) return Promise.resolve(this.view());
    if (!this.pending) this.pending = this.check().finally(() => { this.pending = null; });
    return this.pending;
  }

  async check() {
    try {
      const pkg = await this.remotePackage();
      const latest = String(pkg.version || "");
      const available = newer(latest, VERSION);
      let entries = [];
      if (available) {
        // what's new: the commits down to the one that made this version
        const log = await this.changelog("aegis-burrow").catch(() => ({ entries: [] }));
        for (const e of log.entries) { if (e.version && !newer(e.version, VERSION)) break; entries.push(e); }
      }
      this.state = { current: VERSION, latest, available, checked: Date.now(), error: null,
                     title: entries.find((e) => e.version === latest)?.title || null, entries: entries.slice(0, 12) };
    } catch (e) {
      this.state = { ...this.state, checked: Date.now(), error: e.message };
    }
    return this.view();
  }

  // the update that brought us here, for a few days (the "you're up to date" card)
  get justUpdated() {
    const j = (this.settings.get("updates") || {}).justUpdated;
    return j && j.to === VERSION && Date.now() - j.at < 3 * 86400e3 ? j : null;
  }

  // main's package.json. GitHub's API first: raw.githubusercontent.com is a CDN
  // that can hand out a copy minutes old, so a check would name a version the
  // download no longer is. The raw file is the fallback (no rate limit).
  async remotePackage() {
    if (!MIRROR) {
      try {
        const r = await fetch(`https://api.github.com/repos/${OWN}/contents/package.json?ref=main`,
                              { headers: { "User-Agent": UA, Accept: "application/vnd.github.raw+json" }, signal: AbortSignal.timeout(15000) });
        if (r.ok) return JSON.parse(await r.text());
      } catch { /* fall back */ }
    }
    return getJson(`${RAW}/${OWN}/main/package.json`);
  }

  view() {
    return { ...this.state, auto: this.auto, justUpdated: this.justUpdated, scope: this.scope(), job: this.job, hold: this.hold,
             held: !!(this.state.latest && this.state.available && this.held(this.state.latest)), boot: this.bootView(), kept: this.kept().filter((k) => !k.broken).length,
             repo: `https://github.com/${OWN}`, canRestart: this.scope() !== "manual" };
  }

  async changelog(id) {
    const r = REPOS[id];
    if (!r) throw new Error("No such project.");
    const c = this.logs.get(id);
    if (c && Date.now() - c.at < LOG_TTL) return c;
    try {
      const list = await getJson(`https://api.github.com/repos/${r.repo}/commits?per_page=40`);
      const out = { id, name: r.name, repo: `https://github.com/${r.repo}`, logo: r.logo, at: Date.now(), entries: list.map(entry) };
      this.logs.set(id, out);
      return out;
    } catch (e) {
      if (c) return { ...c, error: e.message };
      throw e;
    }
  }

  // Download, check, swap, restart. Resolves once the new code is in place;
  // the process exits a moment later.
  async apply() {
    if (this.job?.state === "running") return this.job;
    // a standby clone (fleet-ops standbyOn) gets its app from the main host's refresh. Updating
    // itself, it came back as another process its watcher didn't know, and lived on after handing back
    if (process.env.AEGIS_STANDBY === "1") return (this.job = { state: "error", phase: "standby", error: "This is a standby copy: it's updated from the main host, not by itself.", at: Date.now(), to: null });
    const job = this.job = { state: "running", phase: "checking", error: null, at: Date.now(), to: null };
    const work = join(DATA, "update");
    try {
      const st = await this.check();
      if (!st.available) { job.state = "done"; job.phase = "already up to date"; return job; }
      job.to = st.latest;
      job.phase = `downloading ${st.latest}`;
      const buf = await download(`${CODELOAD}/${OWN}/tar.gz/refs/heads/main`, UA);
      rmSync(work, { recursive: true, force: true });
      job.phase = "unpacking";
      const src = join(work, "src");
      unpack(buf, src);
      const pkg = readJson(join(src, "package.json"), {}) || {};
      for (const f of ["aegis/server.mjs", "burrow/index.mjs", "public/ui.css", "bin/aegis", "package.json"]) {
        if (!existsSync(join(src, f))) throw new Error(`The download is missing ${f}; nothing was changed.`);
      }
      if (pkg.name !== "aegis-burrow" || !newer(pkg.version, VERSION)) throw new Error(`The download is ${pkg.name} ${pkg.version}, not a newer Aegis × Burrow; nothing was changed.`);
      job.to = pkg.version;          // what is really installed (the check may have seen an older one)
      job.phase = "checking the download";
      syntaxCheck(src, { log: this.log });
      for (const d of ["bin", "forge"]) {
        try { for (const n of readdirSync(join(src, d))) chmodSync(join(src, d, n), 0o755); } catch { /* no such folder */ }
      }
      job.phase = "installing";
      this.swap(src, pkg.version);
      rmSync(work, { recursive: true, force: true });
      this.noteVersion(pkg.version);
      if (this.hold && !newer(pkg.version, this.hold.version)) this.setHold(null);     // installed on purpose: no longer held
      this.settings.set({ updates: { ...(this.settings.get("updates") || {}), justUpdated: { from: VERSION, to: pkg.version, at: Date.now() } } });
      job.state = "done"; job.phase = `installed ${pkg.version}; restarting`;
      this.log("update: installed", pkg.version, "over", VERSION, "; restarting");
      this.restart();
      return job;
    } catch (e) {
      rmSync(work, { recursive: true, force: true });
      job.state = "error"; job.error = e.message; job.phase = "failed";
      this.log("update: failed:", e.message);
      return job;
    }
  }

  // The same files bin/aegis copy_app copies, swapped in with two renames. The
  // version running now is kept whole in versions/<it>, and the new one goes on
  // trial (data/boot.json) until it has run for a minute.
  swap(src, to, { copy = true } = {}) {
    const next = APP + ".new";
    mkdirSync(VERSIONS, { recursive: true });
    const keep = join(VERSIONS, VERSION);
    rmSync(next, { recursive: true, force: true });
    if (copy) cpSync(src, next, { recursive: true, filter: (p) => !/\/(\.git|node_modules|client|test|docs)(\/|$)/.test(p.slice(src.length)) });
    else renameSync(src, next);
    rmSync(keep, { recursive: true, force: true });
    renameSync(APP, keep);
    try { renameSync(next, APP); } catch (e) { renameSync(keep, APP); throw e; }
    this.stamp(VERSION, `before ${to}`);
    rmSync(join(APP, ".kept.json"), { force: true });
    writeBoot({ state: "trial", from: VERSION, to, at: Date.now(), starts: 0 });
    this.prune();
  }

  // Back (or over) to another version: one kept here first, else that release
  // from GitHub, by its commit. The version left is held back from auto-update.
  async rollback(version, { hold = true } = {}) {
    if (this.job?.state === "running") return this.job;
    const v = String(version || "");
    const job = this.job = { state: "running", phase: "looking", error: null, at: Date.now(), to: v, kind: "rollback" };
    const work = join(DATA, "update");
    try {
      if (!V_RE.test(v)) throw new Error("Pick a version like 2.31.0.");
      if (v === VERSION) throw new Error(`v${v} is the one running.`);
      const k = this.kept().find((x) => x.version === v && !x.broken && x.whole);
      if (k) {
        job.phase = `putting v${v} back`;
        const src = join(VERSIONS, k.dir), staged = join(VERSIONS, `.${k.dir}.staged`);
        rmSync(staged, { recursive: true, force: true });
        renameSync(src, staged);
        try { this.swap(staged, v, { copy: false }); }
        catch (e) { if (existsSync(staged)) renameSync(staged, src); throw e; }
      } else {
        const rel = (await this.versions()).releases.find((r) => r.version === v);
        if (!rel) throw new Error(`v${v} isn't kept here and GitHub's recent history doesn't have it.`);
        job.phase = `downloading v${v}`;
        const buf = await download(`${CODELOAD}/${OWN}/tar.gz/${rel.sha}`, UA);
        rmSync(work, { recursive: true, force: true });
        const src = join(work, "src");
        unpack(buf, src);
        const pkg = readJson(join(src, "package.json"), {}) || {};
        if (pkg.name !== "aegis-burrow" || pkg.version !== v) throw new Error(`That commit is ${pkg.name} ${pkg.version}, not Aegis × Burrow ${v}; nothing was changed.`);
        for (const f of ["aegis/server.mjs", "burrow/index.mjs", "bin/aegis"]) if (!existsSync(join(src, f))) throw new Error(`v${v}'s download is missing ${f}; nothing was changed.`);
        job.phase = "checking the download";
        syntaxCheck(src, { log: this.log });
        for (const d of ["bin", "forge"]) { try { for (const n of readdirSync(join(src, d))) chmodSync(join(src, d, n), 0o755); } catch { /* none */ } }
        job.phase = `installing v${v}`;
        this.swap(src, v);
        rmSync(work, { recursive: true, force: true });
      }
      const down = newer(VERSION, v);
      if (hold && down) this.setHold(VERSION);
      else if (!down && this.hold && !newer(v, this.hold.version)) this.setHold(null);
      this.noteVersion(v);
      this.settings.set({ updates: { ...(this.settings.get("updates") || {}), justUpdated: { from: VERSION, to: v, at: Date.now(), back: down } } });
      job.state = "done"; job.phase = `v${v} is in place; restarting`;
      this.log("update:", down ? "went back to" : "moved to", v, "from", VERSION, down && hold ? `(${VERSION} held back from auto-update)` : "", "; restarting");
      this.restart();
      return job;
    } catch (e) {
      rmSync(work, { recursive: true, force: true });
      job.state = "error"; job.error = e.message; job.phase = "failed";
      this.log("update: going to", v, "failed:", e.message);
      return job;
    }
  }

  // ~/.config/aegis/aegis.json carries the version other apps read
  noteVersion(v) {
    const f = join(CONFIG_DIR, "aegis.json");
    const d = readJson(f, null);
    if (!d || d.home !== HOME) return;
    try { writeFileSync(f + ".tmp", JSON.stringify({ ...d, version: v, updated: Math.floor(Date.now() / 1000) }, null, 2) + "\n"); renameSync(f + ".tmp", f); }
    catch { /* not ours to write */ }
  }

  restart() {
    const scope = this.scope();
    if (scope === "manual") return;               // its own supervisor; the page says to restart it
    if (scope === "background") {
      // no service manager: a detached `aegis start` once this process is gone
      const p = spawn("bash", ["-c", 'sleep 2; exec "$0" start', join(APP, "bin", "aegis")],
                      { detached: true, stdio: "ignore", env: { ...process.env, AEGIS_HOME: HOME } });
      p.unref();
    }
    setTimeout(() => this.exit(), 1200);      // systemd (Restart=always) starts the new code
  }
}
