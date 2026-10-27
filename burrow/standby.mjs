// Burrow, the engine: a tunnel's fallback, for when this machine is down.
//
// When the tunnels go through your VPS (Aegis Relay), its agent (1.5+) can
// stand in for a tunnel while this machine, or the tunnel's own target, isn't
// answering. Per tunnel, t.fallback:
//
//   {kind: "off"}                         nothing (the agent's "home isn't connected" page)
//   {kind: "folder", dir}                 a copy of a folder: a static site, served as it is
//   {kind: "page", title, message}        a message page that sends visitors home every 30 s
//   lock                                  login tunnels only: a password of the fallback's own
//                                         (a scrypt hash, like t.lock); your login lives here
//   status                                {syncedAt, files, bytes, agent, error}
//
// The agent gets the same lock as the tunnel: public, the tunnel's own password
// hash (never the password), or the fallback's. A folder is synced file by file
// over the link's signed control channel, only what changed:
//
//   GET  /standby/<host>                     what the agent has (sha256 per file)
//   PUT  /standby/<host>/file?path=&sha=     one file; the agent checks the body against the signed sha
//   POST /standby/<host>/commit?sha=         the whole manifest and config; swapped in at once
//   DELETE /standby/<host>                   gone (fallback off, tunnel removed)
//
// Synced when it's set, when the folder changes (watched, 5 s quiet first), every
// 10 minutes by hash, when the link comes up and whenever the agent's copy isn't
// the one expected (checked every 30 s: an agent that restarted or was
// reinstalled gets it again).
//
// Limits: 2000 files, 50 MB. Hidden files and folders are left out, and so is
// any link that leads out of the folder.

import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync, watch } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
import { makeLock, SCRYPT } from "./tunnels.mjs";
import { STANDBY_LIMITS, standbyPath, previewToken } from "../relay/agent.mjs";

export { STANDBY_LIMITS };
export const KINDS = ["off", "folder", "page"];
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const MB = (n) => `${(n / 1048576).toFixed(n < 10 * 1048576 ? 1 : 0)} MB`;

// A folder as the agent gets it: -> {files: {path: {sha, size}}, count, bytes, digest, skipped}
// Throws when it's over the limits, or isn't a folder.
export function scanFolder(dir, limits = STANDBY_LIMITS) {
  let root;
  try { root = realpathSync(dir); } catch { throw new Error(`${dir} doesn't exist.`); }
  if (!statSync(root).isDirectory()) throw new Error(`${dir} isn't a folder.`);
  const found = [], skipped = { hidden: 0, outside: 0, other: 0 }, seen = new Set([root]);
  let bytes = 0;
  const walk = (real, rel) => {
    let ents;
    try { ents = readdirSync(real, { withFileTypes: true }); } catch (e) { throw new Error(`Can't read ${join(dir, rel)}: ${e.code || e.message}`); }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.name.startsWith(".")) { skipped.hidden++; continue; }
      const r = rel ? `${rel}/${e.name}` : e.name;
      let p = join(real, e.name), st = lstatSync(p);
      if (st.isSymbolicLink()) {
        try { p = realpathSync(p); } catch { skipped.outside++; continue; }
        if (p !== root && !p.startsWith(root + sep)) { skipped.outside++; continue; }     // a link out of the folder: left out
        st = statSync(p);
      }
      if (st.isDirectory()) { if (!seen.has(p)) { seen.add(p); walk(p, r); } continue; }
      if (!st.isFile() || !standbyPath(r)) { skipped.other++; continue; }
      found.push({ path: r, real: p, size: st.size });
      bytes += st.size;
      if (found.length > limits.files) throw new Error(`${dir} has more than ${limits.files} files: a fallback copy can have ${limits.files} at most.`);
      if (bytes > limits.bytes) throw new Error(`${dir} is more than ${MB(limits.bytes)}: a fallback copy can be ${MB(limits.bytes)} at most.`);
    }
  };
  walk(root, "");
  const files = {};
  for (const f of found) files[f.path] = { sha: sha256(readFileSync(f.real)), size: f.size };
  const digest = sha256(Object.entries(files).map(([p, f]) => `${p}\0${f.sha}\0${f.size}`).join("\n"));
  return { root, files, count: found.length, bytes, digest, skipped };
}

// What the user asked for, checked. prev: the tunnel's fallback until now.
export function cleanFallback(input = {}, t = {}, prev = {}) {
  const kind = input.kind ?? prev.kind ?? "off";
  if (!KINDS.includes(kind)) throw new Error('A fallback is "off", "folder" or "page".');
  const out = { kind, dir: prev.dir || "", title: prev.title || "", message: prev.message || "", lock: prev.lock || null, status: prev.status || null };
  if ("dir" in input) out.dir = String(input.dir || "").trim();
  if ("title" in input) out.title = String(input.title || "").trim();
  if ("message" in input) out.message = String(input.message || "").trim();
  if (out.title.length > 80) throw new Error("The title is longer than 80 characters.");
  if (out.message.length > 1000) throw new Error("The message is longer than 1000 characters.");
  if (input.password) out.lock = makeLock(input.password);
  else if (input.clearPassword) out.lock = null;
  if (kind === "off") return out;
  if (kind === "folder") {
    if (!out.dir) throw new Error("Which folder? Give its full path.");
    let d = out.dir.replace(/^~(?=\/|$)/, homedir());
    if (!isAbsolute(d)) throw new Error("Give the folder's full path (it starts with / or ~/).");
    d = resolve(d);
    if (d === "/" || d === homedir()) throw new Error("Pick the site's own folder, not the whole disk or home.");
    const s = scanFolder(d);
    if (!s.count) throw new Error(`${d} has no files to serve (hidden ones are left out).`);
    out.dir = d;
  }
  if (kind === "page" && !out.message) out.message = "This site is taking a short break. It's back soon.";
  // a tunnel behind your login: that login lives on this machine, down when the fallback shows
  if (t.access === "login" && !out.lock) throw new Error("This tunnel opens with your Aegis login, and that lives on this machine: while it's down nobody could sign in. Give the fallback a password of its own.");
  return out;
}
export function fallbackView(fb) {
  if (!fb) return { kind: "off", dir: "", title: "", message: "", hasPassword: false, status: null };
  return { kind: fb.kind || "off", dir: fb.dir || "", title: fb.title || "", message: fb.message || "", hasPassword: !!fb.lock, status: fb.status || null };
}

export class Standby {
  // tunnels:  the TunnelManager (its raw tunnels: get(port), tunnels Map, save())
  // link:     the RelayLink (link.state, can(), control(), keyBuf(), agent)
  // eligible: (t) => null | why this tunnel's fallback can't be served
  // hostsOf:  (t) => the names of it the VPS carries
  constructor({ tunnels, link, eligible, hostsOf, log, everyMs = 30e3, rescanMs = 10 * 60e3, quietMs = 5000 }) {
    Object.assign(this, { tunnels, link, eligible: eligible || (() => null), hostsOf: hostsOf || ((t) => [t.host].filter(Boolean)), log: log || console.log, everyMs, rescanMs, quietMs });
    this.cache = new Map();        // port -> a scanFolder() result (with dir)
    this.dirty = new Set();        // ports whose folder changed
    this.watchers = new Map();     // port -> {dir, w, timer}
    this.running = null; this.again = false; this.timers = [];
  }
  start() {
    this.timers.push(setInterval(() => this.tick().catch(() => {}), this.everyMs));
    this.timers.push(setInterval(() => { for (const t of this.on()) if (t.fallback.kind === "folder") this.dirty.add(t.port); this.tick().catch(() => {}); }, this.rescanMs));
    for (const x of this.timers) x.unref?.();
    this.rewatch();
    setTimeout(() => this.tick().catch(() => {}), 5000).unref?.();
  }
  stop() { for (const x of this.timers) clearInterval(x); this.timers = []; for (const w of this.watchers.values()) { clearTimeout(w.timer); try { w.w.close(); } catch { /* gone */ } } this.watchers.clear(); }
  on() { return [...this.tunnels.tunnels.values()].filter((t) => t.fallback && t.fallback.kind !== "off"); }

  // the folders being served, watched: a change syncs after quietMs without more
  rewatch() {
    const want = new Map(this.on().filter((t) => t.fallback.kind === "folder").map((t) => [t.port, t.fallback.dir]));
    for (const [port, w] of this.watchers) if (want.get(port) !== w.dir) { clearTimeout(w.timer); try { w.w.close(); } catch { /* gone */ } this.watchers.delete(port); }
    for (const [port, dir] of want) {
      if (this.watchers.has(port)) continue;
      const entry = { dir, w: null, timer: null };
      try {
        entry.w = watch(dir, { recursive: true }, () => {
          clearTimeout(entry.timer);
          entry.timer = setTimeout(() => { this.dirty.add(port); this.tick().catch(() => {}); }, this.quietMs);
          entry.timer.unref?.();
        });
        entry.w.on("error", () => { /* the 10-minute check still runs */ });
      } catch { /* no watching here: the 10-minute check does it */ }
      this.watchers.set(port, entry);
    }
  }

  setStatus(t, st) {
    const before = JSON.stringify(t.fallback.status || null);
    t.fallback.status = { syncedAt: null, files: 0, bytes: 0, agent: false, error: null, ...(t.fallback.status || {}), ...st };
    if (JSON.stringify(t.fallback.status) !== before) this.changed = true;
  }
  // what the agent should hold for this tunnel: {host, hosts, cfg} or {skip: why}
  plan(t) {
    const fb = t.fallback, why = this.eligible(t);
    if (why) return { skip: why };
    if (t.enabled === false) return { skip: "The tunnel is switched off, so nothing stands in for it either." };
    const hosts = [...new Set(this.hostsOf(t).map((h) => h.toLowerCase()))];
    if (!hosts.length) return { skip: "This tunnel's address isn't one your VPS carries." };
    const lock = t.access === "public" ? null : t.access === "password" ? t.lock : fb.lock;
    if (t.access !== "public" && !lock) return { skip: t.access === "login" ? "Give the fallback a password of its own: this tunnel opens with your login, which lives on this machine." : "The tunnel has no password yet." };
    const cfg = { kind: fb.kind, hosts, title: fb.title || "", message: fb.message || "", access: t.access,
                  lock: lock ? { salt: lock.salt, hash: lock.hash, epoch: lock.epoch } : null, scrypt: { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p } };
    return { host: hosts[0], hosts, cfg };
  }
  manifest(t) {
    const c = this.cache.get(t.port);
    if (c && c.dir === t.fallback.dir && !this.dirty.has(t.port)) return c;
    const m = { ...scanFolder(t.fallback.dir), dir: t.fallback.dir };
    this.cache.set(t.port, m);
    this.dirty.delete(t.port);
    return m;
  }

  // Bring the agent in line: what's on, what changed, what went. One at a time.
  tick(force = new Set()) {
    if (this.running) { this.again = true; for (const p of force) (this.forceNext ||= new Set()).add(p); return this.running; }
    this.running = this.reconcile(force).finally(() => {
      this.running = null;
      if (this.changed) { this.changed = false; this.tunnels.save(); }
      if (this.again) { this.again = false; const f = this.forceNext || new Set(); this.forceNext = null; return this.tick(f); }
    });
    return this.running;
  }
  async reconcile(force) {
    const L = this.link, list = this.on();
    if (L.link?.state !== "up") {
      for (const t of list) this.setStatus(t, { agent: false, error: this.plan(t).skip || "The link to your VPS is down right now: the fallback syncs when it's back." });
      return;
    }
    if (!L.can("standby")) {
      const why = `The agent on your VPS is ${L.agent?.version || "too old"}: fallbacks need ${"1.5.0"} (Aegis updates it over the link).`;
      for (const t of list) this.setStatus(t, { agent: false, error: why });
      return;
    }
    let remote;
    try { remote = new Map(((await L.control("GET", "/standby")).sites || []).map((s) => [s.host, s])); }
    catch (e) { for (const t of list) this.setStatus(t, { agent: false, error: `Couldn't ask your VPS: ${e.message}` }); return; }
    const keep = new Set();
    for (const t of list) {
      const p = this.plan(t);
      if (p.skip) { this.setStatus(t, { agent: false, error: p.skip }); continue; }
      keep.add(p.host);
      try {
        const m = t.fallback.kind === "folder" ? this.manifest(t) : null;
        const fp = sha256(JSON.stringify(p.cfg) + (m ? m.digest : ""));
        const there = remote.get(p.host);
        if (!force.has(t.port) && there?.fp === fp) { this.setStatus(t, { agent: true, error: null, files: there.files, bytes: there.bytes, syncedAt: t.fallback.status?.syncedAt || there.at }); continue; }
        const r = await this.push(p, m, fp);
        this.setStatus(t, { agent: true, error: null, syncedAt: Date.now(), files: r.files, bytes: r.bytes, sent: r.sent });
        this.log(`standby: tunnel ${t.port}'s fallback is on the VPS (${t.fallback.kind}${m ? `, ${r.files} files, ${r.sent} sent` : ""})`);
      } catch (e) {
        this.setStatus(t, { agent: true, error: e.message });
        this.log(`standby: tunnel ${t.port}: ${e.message}`);
      }
    }
    for (const host of remote.keys()) {
      if (keep.has(host)) continue;
      try { await L.control("DELETE", `/standby/${host}`); this.log(`standby: ${host}'s fallback removed from the VPS`); } catch (e) { this.log(`standby: couldn't remove ${host}'s:`, e.message); }
    }
  }
  // only the files the agent doesn't have, then the whole manifest at once
  async push(p, m, fp) {
    const L = this.link, base = `/standby/${p.host}`;
    let sent = 0;
    if (m) {
      let have = {};
      try { have = (await L.control("GET", base)).files || {}; } catch { have = {}; }
      for (const [path, f] of Object.entries(m.files)) {
        if (have[path]?.sha === f.sha) continue;
        const buf = readFileSync(join(m.root, ...path.split("/")));
        if (sha256(buf) !== f.sha) throw new Error(`${path} changed while it was being sent: trying again shortly`);
        await L.control("PUT", `${base}/file?path=${encodeURIComponent(path)}&sha=${f.sha}`, buf, 120000);
        sent++;
      }
    }
    const body = Buffer.from(JSON.stringify({ ...p.cfg, fp, files: m ? m.files : {} }));
    const r = await L.control("POST", `${base}/commit?sha=${sha256(body)}`, body, 60000);
    return { files: r.files, bytes: r.bytes, sent };
  }

  // ---------------- what the routes call
  view(port) {
    const t = this.tunnels.get(port);
    if (!t) throw new Error("No such tunnel.");
    const why = this.eligible(t);
    return { port: t.port, access: t.access, ...fallbackView(t.fallback), offered: !why, why, hosts: why ? [] : this.hostsOf(t), limits: STANDBY_LIMITS };
  }
  async configure(port, input) {
    const t = this.tunnels.get(port);
    if (!t) throw new Error("No such tunnel.");
    const kind = input.kind ?? t.fallback?.kind ?? "off";
    if (kind !== "off") { const why = this.eligible(t); if (why) throw new Error(why); }
    const fb = cleanFallback(input, t, t.fallback || {});
    if (kind === "off") fb.status = null;
    t.fallback = fb;
    this.tunnels.save();
    this.cache.delete(t.port); this.dirty.add(t.port);
    this.rewatch();
    await this.tick(new Set([t.port]));
    return this.view(port);
  }
  async sync(port) {
    const t = this.tunnels.get(port);
    if (!t) throw new Error("No such tunnel.");
    if (!t.fallback || t.fallback.kind === "off") throw new Error("This tunnel has no fallback.");
    this.dirty.add(t.port);
    await this.tick(new Set([t.port]));
    return this.view(port);
  }
  // a link that shows the fallback even while this machine is up (ten minutes)
  preview(port) {
    const t = this.tunnels.get(port);
    if (!t) throw new Error("No such tunnel.");
    if (!t.fallback || t.fallback.kind === "off") throw new Error("Turn the fallback on first.");
    if (!t.fallback.status?.syncedAt || t.fallback.status.error) throw new Error(t.fallback.status?.error || "The fallback isn't on your VPS yet.");
    const host = this.hostsOf(t)[0];
    if (!host) throw new Error("This tunnel's address isn't one your VPS carries.");
    const token = previewToken(this.link.keyBuf(), host);
    return { url: `https://${host}/?__aegis_standby=${encodeURIComponent(token)}`, expires: Number(token.split(".")[1]) };
  }
  // the routes, for the dashboard (/__gate/api/tunnels/PORT/fallback…) and the control socket
  async route(method, path, readJson) {
    const m = /^\/tunnels\/(\d{1,5})\/fallback(\/sync|\/preview)?$/.exec(path);
    if (!m) return null;
    const port = Number(m[1]);
    try {
      if (!m[2] && method === "GET") return { status: 200, json: this.view(port) };
      if (!m[2] && (method === "PUT" || method === "POST")) return { status: 200, json: await this.configure(port, (await readJson()) || {}) };
      if (m[2] === "/sync" && method === "POST") return { status: 200, json: await this.sync(port) };
      if (m[2] === "/preview" && method === "POST") return { status: 200, json: this.preview(port) };
      return { status: 405, json: { error: "GET, PUT; POST …/sync, …/preview" } };
    } catch (e) { return { status: 400, json: { error: e.message } }; }
  }
}
