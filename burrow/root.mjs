// Burrow, the engine: administrator (root) access for addon scripts.
//
// Some addons need root to install, update or uninstall (a mail server that
// configures Postfix), or for one action. Their manifest says so and why:
//
//   "requires": {"root": "Installs and configures Postfix and OpenDKIM"}
//   "actions": [{"id": "rotate-keys", …, "root": true}]
//
// Scripts run unattended with stdin closed, so a sudo that asks would hang.
// Instead, before such a job starts, the host:
//
//   1. checks `sudo -k -n true` (short timeout). Passwordless sudo: the user is
//      only warned and asked to go on. Otherwise the user types their password,
//      checked with `sudo -S -k -p '' -v` (fed on stdin, never argv or env);
//      a wrong one runs nothing.
//   2. keeps the password in memory only, under a random token for that one
//      job, deleted when the job ends (and after an hour at most). Never on
//      disk, in logs, in the job's output, in settings or in an environment.
//   3. runs the script with ADDON_ROOT=1, ADDON_ASKPASS_TOKEN=<token> and
//      SUDO_ASKPASS=<bin/aegis-askpass>. The script calls `sudo -A …`; sudo
//      runs the helper, which asks the control socket (POST /askpass, token in
//      the body) for the password and prints it.
//
// Aegis's own systemd unit may sandbox it (NoNewPrivileges=, ProtectSystem=),
// and everything it starts inherits that, so sudo can't work from it. This
// user's systemd manager isn't sandboxed: a transient service it starts
// (systemd-run --user, not --scope) is the manager's child, not ours. Where
// Aegis is sandboxed and that manager is there, the sudo checks and the root
// jobs run that way (see userManager()), so the dashboard can still ask for the
// password and run the job itself.
//
// Only the control socket answers /askpass (mode 600, this user), and only for
// a token of a job that is still running. The dashboard has no such route.
// Automatic paths (default addons, the watchdog, rescue) never get a token:
// they skip what needs root and leave a notice instead.

import { spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ASKPASS = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "aegis-askpass");
export const TOKEN_TTL = 3600e3;                 // an hour at most, whatever the job does
const TOKEN_RE = /^[0-9a-f]{64}$/;
const CHECK_TTL = 60e3;                          // how long a `sudo -n` answer is reused
const FAILS_MAX = 5, FAILS_WINDOW = 5 * 60e3;   // wrong passwords before a pause

// Why sudo can't work from this process at all, whatever the password:
// systemd's NoNewPrivileges=, or a read-only /etc (ProtectSystem=strict|full),
// both inherited by everything Aegis starts. null when neither.
export function sandboxed({ status = "/proc/self/status", mountinfo = "/proc/self/mountinfo" } = {}) {
  try { if (/^NoNewPrivs:\s*1\s*$/m.test(readFileSync(status, "utf8"))) return "Aegis runs with NoNewPrivileges (its systemd unit), so nothing it starts can use sudo"; } catch { /* not Linux */ }
  try {
    let best = null;
    for (const line of readFileSync(mountinfo, "utf8").split("\n")) {
      const f = line.split(" ");
      const point = f[4], opts = f[5] || "";
      if (!point || !("/etc/".startsWith(point.endsWith("/") ? point : point + "/"))) continue;
      if (!best || point.length >= best.point.length) best = { point, ro: opts.split(",").includes("ro") };
    }
    if (best?.ro) return "Aegis runs with a read-only system (ProtectSystem= in its systemd unit), so even root can't change /etc from it";
  } catch { /* not Linux */ }
  return null;
}

// ---------------- outside the sandbox
// The user's systemd manager, when it can run things without our sandbox:
// {args, env} for `systemd-run` (a transient service, waited for, stdio piped
// through), or null. A yes is kept; a no is asked again after a minute.
let outsideSeen = { at: 0, value: null };
export async function userManager({ now = Date.now() } = {}) {
  if (outsideSeen.value || now - outsideSeen.at < 60e3 && outsideSeen.at) return outsideSeen.value;
  let value = null;
  try {
    const uid = process.getuid?.();
    const run = process.env.XDG_RUNTIME_DIR || `/run/user/${uid}`;
    const bin = (process.env.PATH || "/usr/bin:/bin").split(":").map((d) => join(d, "systemd-run")).find((f) => existsSync(f));
    if (uid != null && bin && existsSync(join(run, "bus"))) {
      const o = { args: ["--user", "--wait", "--pipe", "--quiet", "--collect", "--setenv=LC_ALL=C"],
                  env: { XDG_RUNTIME_DIR: run, DBUS_SESSION_BUS_ADDRESS: `unix:path=${join(run, "bus")}` } };
      const r = await runOutside(o, ["cat", "/proc/self/status"], { timeout: 10000 });
      if (r.code === 0 && /^NoNewPrivs:\s*0\s*$/m.test(r.out)) value = o;
    }
  } catch { value = null; }
  outsideSeen = { at: now, value };
  return value;
}
// CMD as a transient service of the user's manager -> {code, out, err, missing}.
// Killing systemd-run leaves the service running, so a timeout stops the unit.
export function runOutside(o, cmd, { input = null, timeout = 10000, cwd = null, name = "aegis-sudo" } = {}) {
  return new Promise((done) => {
    const unit = `${name}-${randomBytes(4).toString("hex")}`;
    const args = [...o.args, `--unit=${unit}`, ...(cwd ? [`--working-directory=${cwd}`] : []), "--", ...cmd];
    let p;
    try { p = spawn("systemd-run", args, { env: { PATH: process.env.PATH || "/usr/bin:/bin", LC_ALL: "C", ...o.env }, stdio: ["pipe", "pipe", "pipe"], detached: true }); }
    catch (err) { return done({ code: 127, out: "", err: err.message, missing: true }); }
    let out = "", err = "", finished = false;
    const end = (r) => { if (finished) return; finished = true; clearTimeout(t); done(r); };
    const t = setTimeout(() => { stopUnit(o, unit, "SIGKILL"); try { process.kill(-p.pid, "SIGKILL"); } catch { /* gone */ } end({ code: 124, out, err: err + "\n(timed out)", missing: false }); }, timeout);
    p.stdout.on("data", (x) => { out += x; });
    p.stderr.on("data", (x) => { err += x; });
    p.on("error", (x) => end({ code: 127, out, err: x.message, missing: false }));
    p.on("close", (code) => end({ code: code ?? 1, out, err, missing: code !== 0 && /Failed to (locate|find) executable|status=203/i.test(err) }));
    p.stdin.on("error", () => { /* it didn't read it */ });
    p.stdin.end(input == null ? "" : input);
  });
}
// signal every process of a transient unit (systemctl --user kill)
export function stopUnit(o, unit, signal = "SIGTERM") {
  try {
    const p = spawn("systemctl", ["--user", "kill", `--signal=${signal}`, unit], { env: { PATH: process.env.PATH || "/usr/bin:/bin", ...o.env }, stdio: "ignore", detached: true });
    p.on("error", () => {}); p.unref();
  } catch { /* nothing to stop */ }
}
// A root job's script, outside: its environment goes in on stdin (never argv,
// never a file), the launcher evals it, then runs the script with stdin closed.
export const OUTSIDE_LAUNCH = 'eval "$(cat)"; exec bash -- "$0" </dev/null';
const BASH_OWN = new Set(["_", "UID", "EUID", "PPID", "SHELLOPTS", "BASHOPTS", "BASHPID", "BASH_VERSINFO", "GROUPS"]);   // bash's read-only names
export function envScript(env) {
  let s = "";
  for (const [k, v] of Object.entries(env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || BASH_OWN.has(k) || v == null) continue;
    s += `export ${k}='${String(v).replace(/'/g, "'\\''")}'\n`;
  }
  return s;
}

// The real sudo: `sudo ARGS`, with input on stdin, in a session of its own
// (detached: no controlling terminal, so it never prompts on one).
// -> {code, out, err, missing}
// With outside ({args, env} from userManager()), through the user's manager.
export function runSudo(args, { input = null, timeout = 10000, outside = null } = {}) {
  if (outside) return runOutside(outside, ["sudo", ...args], { input, timeout });
  return new Promise((done) => {
    const e = { ...process.env, LC_ALL: "C" };     // English messages, which are matched below
    delete e.SUDO_ASKPASS;
    let p;
    try { p = spawn("sudo", args, { env: e, stdio: ["pipe", "pipe", "pipe"], detached: true }); }
    catch (err) { return done({ code: 127, out: "", err: err.message, missing: true }); }
    let out = "", err = "", finished = false;
    const end = (r) => { if (finished) return; finished = true; clearTimeout(t); done(r); };
    const t = setTimeout(() => { try { process.kill(-p.pid, "SIGKILL"); } catch { /* gone */ } end({ code: 124, out, err: err + "\n(timed out)", missing: false }); }, timeout);
    p.stdout.on("data", (x) => { out += x; });
    p.stderr.on("data", (x) => { err += x; });
    p.on("error", (x) => end({ code: 127, out, err: x.message, missing: x.code === "ENOENT" }));
    p.on("close", (code) => end({ code: code ?? 1, out, err, missing: false }));
    p.stdin.on("error", () => { /* sudo didn't read it */ });
    p.stdin.end(input == null ? "" : input);
  });
}

const notAllowed = (s) => /not in the sudoers|not allowed to (run|execute)|may not run sudo/i.test(s);
const wrongPassword = (s) => /incorrect password|Sorry, try again|no password was provided|Authentication failure/i.test(s);

export class RootError extends Error {
  constructor(message, status, extra) { super(message); this.status = status; this.extra = extra || {}; }
}

export class RootAccess {
  // sudo:  (args, {input, timeout}) => Promise<{code, out, err, missing}>  (injectable: tests never run sudo)
  // guard: () => null | "why sudo can't work from here"
  // outside: async () => {args, env} | null, a way around the guard (userManager();
  //          none by default when the guard is injected, so tests never reach systemd)
  constructor({ sudo, guard, outside, askpass = ASKPASS, ttl = TOKEN_TTL, now = () => Date.now() } = {}) {
    Object.assign(this, { sudo: sudo || ((a, o) => runSudo(a, o)), guard: guard || (() => sandboxed()), askpass, ttl, now });
    this.findOutside = outside || (guard ? async () => null : () => userManager());
    this.outside = null;          // set by check(): root work goes through the user's manager
    this.tokens = new Map();      // token -> {password|null, expires, job}
    this.checked = null;          // {at, value}
    this.fails = [];
    this.sweeper = setInterval(() => this.sweep(), 60e3);
    this.sweeper.unref?.();
  }

  // Can this host use sudo, and does it ask for a password?
  // -> {sudo: bool, passwordless: bool, why: string|null}
  async check(fresh = false) {
    if (!fresh && this.checked && this.now() - this.checked.at < CHECK_TTL) return this.checked.value;
    let value, blocked = this.guard();
    this.outside = null;
    if (blocked) { const o = await this.findOutside().catch(() => null); if (o) { this.outside = o; blocked = null; } }
    if (blocked) value = { sudo: false, passwordless: false, why: blocked + "." };
    else {
      // -k: never a credential cached by an earlier check or validation
      const r = await this.sudo(["-k", "-n", "true"], { timeout: 8000, outside: this.outside });
      if (r.missing) value = { sudo: false, passwordless: false, why: "sudo isn't installed on this machine." };
      else if (r.code === 0) value = { sudo: true, passwordless: true, why: null };
      else if (/no new privileges/i.test(r.err)) value = { sudo: false, passwordless: false, why: "Aegis runs with NoNewPrivileges (its systemd unit), so nothing it starts can use sudo." };
      else if (notAllowed(r.err)) value = { sudo: false, passwordless: false, why: "This user isn't allowed to use sudo." };
      else value = { sudo: true, passwordless: false, why: null };
    }
    this.checked = { at: this.now(), value };
    return value;
  }

  // Is this the user's sudo password? -> {ok: true} | throws RootError (403: wrong, can't; 429: too many)
  async validate(password) {
    const pw = String(password ?? "");
    if (!pw) throw new RootError("Type your password.", 403, { badPassword: true });
    if (pw.length > 1024 || /[\r\n\0]/.test(pw)) throw new RootError("That isn't a password sudo can take.", 403, { badPassword: true });
    this.fails = this.fails.filter((t) => this.now() - t < FAILS_WINDOW);
    if (this.fails.length >= FAILS_MAX) throw new RootError("Too many wrong passwords. Wait a few minutes and try again.", 429, { badPassword: true });
    // -S: the password on stdin; -k: ask even if cached, and cache nothing; -p '': no prompt text
    const r = await this.sudo(["-S", "-k", "-p", "", "-v"], { input: pw + "\n", timeout: 15000, outside: this.outside });
    if (r.missing) throw new RootError("sudo isn't installed on this machine.", 403, { noSudo: true, why: "sudo isn't installed on this machine." });
    if (r.code === 0) { this.fails = []; return { ok: true }; }
    if (notAllowed(r.err)) throw new RootError("This user isn't allowed to use sudo.", 403, { noSudo: true, why: "This user isn't allowed to use sudo." });
    if (/no new privileges/i.test(r.err)) throw new RootError("Aegis runs with NoNewPrivileges, so it can't use sudo.", 403, { noSudo: true, why: "Aegis runs with NoNewPrivileges (its systemd unit), so nothing it starts can use sudo." });
    this.fails.push(this.now());
    if (wrongPassword(r.err) || r.code === 1) throw new RootError("That password didn't work for sudo.", 403, { badPassword: true });
    throw new RootError(`sudo said: ${String(r.err).trim().split("\n").pop().slice(0, 200) || `exit ${r.code}`}`, 403, { badPassword: true });
  }

  // A token for one job. The password (null for passwordless sudo) stays here, in memory.
  issue(password = null, job = null) {
    const token = randomBytes(32).toString("hex");
    this.tokens.set(token, { password: password == null ? null : String(password), expires: this.now() + this.ttl, job });
    return token;
  }
  bind(token, job) { const t = this.tokens.get(token); if (t) t.job = job; }
  // the password for a live token; null for unknown, expired or passwordless
  get(token) {
    if (typeof token !== "string" || !TOKEN_RE.test(token)) return null;
    let hit = null;
    for (const [k, v] of this.tokens) {                 // constant-time compare, whatever the map does
      if (timingSafeEqual(Buffer.from(k), Buffer.from(token))) hit = [k, v];
    }
    if (!hit) return null;
    if (this.now() >= hit[1].expires) { this.drop(hit[0]); return null; }
    return hit[1].password;
  }
  has(token) { return typeof token === "string" && this.tokens.has(token) && this.now() < this.tokens.get(token).expires; }
  drop(token) {
    const t = this.tokens.get(token);
    if (t) { t.password = null; this.tokens.delete(token); }
  }
  sweep() { for (const [k, v] of this.tokens) if (this.now() >= v.expires) this.drop(k); }
  stop() { clearInterval(this.sweeper); for (const k of [...this.tokens.keys()]) this.drop(k); }

  // The environment a root job's script gets (never the password itself).
  env(token) { return { ADDON_ROOT: "1", ADDON_ASKPASS_TOKEN: token, SUDO_ASKPASS: this.askpass }; }

  // The control socket's route: POST /askpass {"token": "…"} -> the password as
  // text/plain, or 404. Nothing else; never on the dashboard.
  async route(method, path, readJson) {
    if (path !== "/askpass" && !path.startsWith("/askpass/")) return null;
    if (method !== "POST" || path !== "/askpass") return { status: 405, json: { error: "POST /askpass {\"token\": …}" } };
    let b = {};
    try { b = (await readJson()) || {}; } catch { return { status: 400, json: { error: "bad JSON" } }; }
    const live = this.has(b.token);
    const pw = live ? this.get(b.token) : null;
    if (!live || pw == null) return { status: 404, json: { error: "no such token" } };
    return { status: 200, body: pw + "\n", headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } };
  }
}

// The command to tell someone who can't sudo from here.
// cmd: what to type there (aegis addons install ID): it runs the script in that terminal, where sudo can ask
export const terminalHint = (m, cmd) => cmd ? `Run it in a terminal on this machine: ${cmd}` : `Ask an administrator, or run the installer from a terminal${m?.homepage ? ` (see ${m.homepage})` : ""}.`;
export const terminalCommand = (id, op, action) => `aegis addons ${op === "action" || op === "down" ? `action ${id} ${action}` : `${op} ${id}`}`;
