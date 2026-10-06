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
//   auto        settings.updates.auto: apply by itself when a check finds one.
//   changelog() the newest commits of Aegis × Burrow, Selkies Forge and the
//               Weft Architecture, for Settings → Updates (cached for an hour).
//
// AEGIS_REPO (owner/name) points it at another copy, e.g. a fork, and
// AEGIS_UPDATE_MIRROR (a base URL serving /<repo>/main/package.json and
// /<repo>/tar.gz/refs/heads/main, like GitHub's) at a mirror or a test server.

import { chmodSync, cpSync, existsSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { APP, HOME, DATA, CONFIG_DIR, VERSION, readJson } from "./config.mjs";
import { download, unpack } from "../burrow/archive.mjs";
import { versionTuple } from "../burrow/addons.mjs";

export const REPOS = {
  "aegis-burrow": { name: "Aegis × Burrow", repo: process.env.AEGIS_REPO || "alexd-aero/aegis-burrow", logo: "/__gate/logos/aegis-burrow.svg" },
  "selkies-forge": { name: "Selkies Forge", repo: "adatskov-wcpss/animated-fiesta", logo: "/__gate/logos/forge.svg" },
  weft: { name: "Weft Architecture", repo: "alexd-aero/weft", logo: "/__gate/logos/weft.svg" },
};
const OWN = REPOS["aegis-burrow"].repo;
const UA = `aegis-burrow/${VERSION} (+https://github.com/${OWN})`;
const MIRROR = process.env.AEGIS_UPDATE_MIRROR?.replace(/\/$/, "");
const RAW = MIRROR || "https://raw.githubusercontent.com", CODELOAD = MIRROR || "https://codeload.github.com";
const CHECK_EVERY = 30 * 60 * 1000;      // in the background; a page that opens checks sooner (fresh())
const FRESH = 2 * 60 * 1000;             // a check younger than this is good enough for a page
const LOG_TTL = 3600 * 1000;
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
      if (this.state.available && this.auto && !this.job) { this.log("update: applying", this.state.latest, "by itself (auto-update is on)"); await this.apply(); }
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
      const pkg = await getJson(`${RAW}/${OWN}/main/package.json`);
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

  view() {
    return { ...this.state, auto: this.auto, justUpdated: this.justUpdated, scope: this.scope(), job: this.job,
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
      for (const d of ["bin", "forge"]) {
        try { for (const n of readdirSync(join(src, d))) chmodSync(join(src, d, n), 0o755); } catch { /* no such folder */ }
      }
      job.phase = "installing";
      this.swap(src);
      rmSync(work, { recursive: true, force: true });
      this.noteVersion(pkg.version);
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

  // The same files bin/aegis copy_app copies, swapped in with two renames.
  swap(src) {
    const next = APP + ".new", prev = APP + ".prev";
    rmSync(next, { recursive: true, force: true });
    cpSync(src, next, { recursive: true, filter: (p) => !/\/(\.git|node_modules|client|test|docs)(\/|$)/.test(p.slice(src.length)) });
    rmSync(prev, { recursive: true, force: true });
    renameSync(APP, prev);
    try { renameSync(next, APP); } catch (e) { renameSync(prev, APP); throw e; }
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
