// Burrow, the engine: a serveo link to the dashboard.
//
// `ssh -R 80:localhost:PORT serveo.net` gives the dashboard a public HTTPS
// address (https://<id>.serveousercontent.com) with no account and no domain:
// handy for the first run, from a phone, before Cloudflare is linked. It goes
// through the same gate as everything else: serveo's visitors are remote
// (setup needs the one-time token, sign-in needs the password), and their real
// address comes from X-Real-Ip for the lockout.
//
// A key of our own (data/serveo/id_ed25519) keeps the name the same across
// reconnects. The ssh flags are deliberate: serveo authorises anonymous
// tunnels over keyboard-interactive, so BatchMode=yes or
// NumberOfPasswordPrompts=0 would break it.

import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const URL_RE = /https:\/\/[a-z0-9.-]+\.serveousercontent\.com/i;
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;

export class Serveo {
  constructor({ dataDir, log }) {
    this.dir = join(dataDir, "serveo");
    this.log = log || console.log;
    this.proc = null;
    this.url = null;
    this.port = null;
    this.error = null;
    this.wanted = false;
    this.backoff = 5000;
    this.since = null;
  }

  host() { try { return this.url ? new URL(this.url).host.toLowerCase() : null; } catch { return null; } }

  key() {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const k = join(this.dir, "id_ed25519");
    if (!existsSync(k)) execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "aegis-burrow serveo", "-f", k], { stdio: "ignore" });
    return k;
  }

  // Forward serveo to a plain-HTTP port on this machine.
  start(port) {
    this.wanted = true;
    this.port = port;
    if (this.proc) return;
    let key;
    try { key = this.key(); } catch (e) { this.error = `ssh-keygen is missing or failed: ${e.message}`; return; }
    const args = ["-T", "-n", "-o", "StrictHostKeyChecking=no", "-o", `UserKnownHostsFile=${join(this.dir, "known_hosts")}`,
                  "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
                  "-o", "ConnectTimeout=20", "-i", key, "-o", "IdentitiesOnly=yes", "-R", `80:localhost:${port}`, "serveo.net"];
    const p = spawn("ssh", args, { stdio: ["ignore", "pipe", "pipe"] });
    this.proc = p;
    this.error = null;
    const feed = (d) => {
      const m = URL_RE.exec(String(d).replace(ANSI, ""));
      if (m && m[0] !== this.url) { this.url = m[0]; this.since = Date.now(); this.backoff = 5000; this.log("serveo:", this.url); }
      else if (!m && /denied|refused|error|failed/i.test(String(d))) this.error = String(d).replace(ANSI, "").trim().split("\n").pop().slice(0, 200);
    };
    p.stdout.on("data", feed);
    p.stderr.on("data", feed);
    p.on("error", (e) => { this.error = e.code === "ENOENT" ? "ssh is not installed" : e.message; });
    p.on("exit", (code) => {
      this.proc = null;
      if (!this.wanted) return;
      this.error = this.error || `ssh exited (${code})`;
      setTimeout(() => this.wanted && this.start(this.port), this.backoff);
      this.backoff = Math.min(this.backoff * 2, 5 * 60000);
    });
  }

  stop() {
    this.wanted = false;
    if (this.proc) { try { this.proc.kill(); } catch { /* gone */ } }
    this.proc = null;
    this.url = null;
  }

  state() { return { on: this.wanted, url: this.url, up: !!(this.proc && this.url), error: this.url ? null : this.error, since: this.since }; }
}
