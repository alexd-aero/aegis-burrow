// Termix (https://github.com/Termix-SSH/Termix): SSH terminals, files and
// hosts in the browser. Optional. When it is set up, the dashboard's home
// offers it next to Tunnels and every non-Aegis path on the dashboard's
// address is Termix, behind the same login.
//
// Aegis can install it (one Docker container, bound to 127.0.0.1 only) or
// use one that already runs (settings.termix.upstream).

import { execFile } from "node:child_process";
import { connect as netConnect } from "node:net";

const IMAGE = "ghcr.io/lukegus/termix:latest";
const CONTAINER = "aegis-termix";
const VOLUME = "aegis-termix-data";

function docker(args, timeout = 30000) {
  return new Promise((resolve) => execFile("docker", args, { timeout, maxBuffer: 8 << 20 },
    (err, out, errOut) => resolve({ code: err ? (err.code ?? 1) : 0, out: String(out || "").trim(), err: String(errOut || err?.message || "").trim() })));
}

function portFree(port) {
  return new Promise((resolve) => {
    const s = netConnect({ host: "127.0.0.1", port, timeout: 800 });
    s.once("connect", () => { s.destroy(); resolve(false); });
    s.once("timeout", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(true));
  });
}

export class Termix {
  constructor({ settings, log }) {
    this.settings = settings;
    this.log = log;
    this.job = null;        // { state, lines, error } while installing
  }

  config() { return this.settings.get("termix"); }

  async status() {
    const t = this.config();
    const out = { configured: !!t, upstream: t?.upstream || null, managed: !!t?.container, job: this.job ? { ...this.job } : null };
    if (t?.container) {
      const r = await docker(["inspect", "-f", "{{.State.Status}}", t.container], 8000);
      out.container = r.code === 0 ? r.out : "missing";
    }
    if (t?.upstream) {
      const u = new URL(t.upstream);
      out.up = !(await portFree(Number(u.port || (u.protocol === "https:" ? 443 : 80))));
    }
    out.docker = (await docker(["version", "--format", "{{.Server.Version}}"], 8000)).code === 0;
    return out;
  }

  // Pull and start the container; progress is polled through status().
  install() {
    if (this.job?.state === "running") throw new Error("Termix is already being installed.");
    if (this.config()) throw new Error("Termix is already set up.");
    const job = { state: "running", lines: [], error: null, started: Date.now() };
    this.job = job;
    const say = (l) => { job.lines.push(l); if (job.lines.length > 40) job.lines.shift(); };
    (async () => {
      if ((await docker(["version"], 10000)).code !== 0) throw new Error("Docker is not available to Aegis (is this user in the docker group?).");
      let port = 4300;
      while (port < 4400 && !(await portFree(port))) port++;
      say(`pulling ${IMAGE} (a few hundred MB, once)…`);
      const pull = await docker(["pull", IMAGE], 15 * 60000);
      if (pull.code !== 0) throw new Error(`docker pull failed: ${pull.err.split("\n").pop()}`);
      say("starting the container…");
      await docker(["rm", "-f", CONTAINER], 30000);
      const r = await docker(["run", "-d", "--name", CONTAINER, "--restart", "unless-stopped",
        "-p", `127.0.0.1:${port}:8080`, "-e", "PORT=8080", "-v", `${VOLUME}:/app/data`,
        "--label", "io.aegis.app=termix", IMAGE], 120000);
      if (r.code !== 0) throw new Error(`docker run failed: ${r.err.split("\n").pop()}`);
      say(`waiting for Termix on 127.0.0.1:${port}…`);
      for (let i = 0; i < 90 && (await portFree(port)); i++) await new Promise((res) => setTimeout(res, 1000));
      this.settings.set({ termix: { upstream: `http://127.0.0.1:${port}`, container: CONTAINER } });
      say("Termix is ready. Create its own account on first open.");
      job.state = "done";
      this.log("termix: installed on", port);
    })().catch((e) => { job.state = "error"; job.error = e.message; say(e.message); this.log("termix: install failed", e.message); });
    return { ok: true };
  }

  // Create Termix's first account (it becomes Termix's admin). Termix needs a
  // few seconds after its port opens before its API answers.
  async createUser(username, password, timeoutMs = 120000) {
    const t = this.config();
    if (!t?.upstream) throw new Error("Termix is not set up.");
    const until = Date.now() + timeoutMs;
    let last = "";
    while (Date.now() < until) {
      try {
        const r = await fetch(new URL("/users/create", t.upstream), {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }), signal: AbortSignal.timeout(8000),
        });
        const j = await r.json().catch(() => ({}));
        if (r.ok) return { ok: true };
        if (r.status === 409) return { ok: true, existed: true };
        if (r.status === 403) throw new Error(j.error || "Termix does not allow new accounts.");
        last = j.error || `HTTP ${r.status}`;
      } catch (e) { if (/allow/.test(e.message)) throw e; last = e.message; }
      await new Promise((res) => setTimeout(res, 2500));
    }
    throw new Error(`Termix did not accept the account: ${last}`);
  }

  // Forget Termix; a container Aegis made is removed, its data volume kept.
  async remove() {
    const t = this.config();
    if (t?.container) await docker(["rm", "-f", t.container], 60000);
    this.settings.set({ termix: null });
    this.job = null;
    return { ok: true, kept: t?.container ? VOLUME : null };
  }
}
