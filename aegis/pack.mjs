// The pack: what Aegis offers to set up right after the first login.
//
//   Burrow         tunnels; built into Aegis, on unless you untick it
//   Termix         SSH terminals in the browser (Docker), with an account
//                  whose username and password you choose on the same page
//   Selkies Forge  Linux desktops in the browser (its own installer, unattended)
//
// Each can be left out, or the whole pack skipped ("I don't want this pack").
// Everything here can also be done later from Settings. The choice is
// remembered (state.json: pack), so the welcome page only offers it once.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const FORGE_INSTALL = "https://raw.githubusercontent.com/adatskov-wcpss/animated-fiesta/main/docker.sh";
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r/g;

export function forgeInstalled() {
  const home = process.env.FORGE_HOME || join(homedir(), ".selkies-forge");
  return existsSync(join(home, "app", "engine.py"));
}

export class Pack {
  constructor({ settings, termix, log, tunnels }) {
    this.tunnels = tunnels;
    this.found = null;
    this.settings = settings;
    this.termix = termix;
    this.log = log;
    this.job = null;
  }

  // what is already on this machine (Termix on any port, a Forge)
  async detect() {
    const termix = this.settings.get("termix") ? null : await this.termix.detect(this.tunnels).catch(() => null);
    this.found = { termix, forge: forgeInstalled(), at: Date.now() };
    return this.found;
  }

  status() {
    const p = this.settings.get("pack") || {};
    return {
      decided: !!p.decided, skipped: !!p.skipped, at: p.at || null,
      burrow: (this.settings.get("modules") || {}).burrow !== false,
      termix: !!this.settings.get("termix"),
      forge: forgeInstalled(),
      found: this.found,
      job: this.job ? { ...this.job, steps: this.job.steps.map((s) => ({ ...s, lines: s.lines.slice(-6) })) } : null,
    };
  }

  skip() {
    this.settings.set({ pack: { decided: true, skipped: true, at: Date.now() } });
    this.log("pack: skipped");
  }

  // choice = { burrow: bool, forge: bool, termix: null | { username, password } }
  run(choice) {
    if (this.job?.state === "running") throw new Error("The pack is already being set up.");
    const steps = [];
    const burrow = choice.burrow !== false;
    steps.push({ id: "burrow", label: burrow ? "Burrow: on" : "Burrow: off", state: "waiting", lines: [] });
    let termix = null;
    let linkTermix = null;
    if (choice.termix && choice.termix.link && this.found?.termix) {
      linkTermix = this.found.termix;
      steps.push({ id: "termix", label: "Termix (already here)", state: "waiting", lines: [] });
    } else if (choice.termix) {
      const username = String(choice.termix.username || "").trim();
      const password = String(choice.termix.password || "");
      if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) throw new Error("Termix username: 2-64 letters, digits, . _ @ -");
      if (password.length < 8) throw new Error("Termix password: at least 8 characters.");
      termix = { username, password };
      steps.push({ id: "termix", label: "Termix", state: "waiting", lines: [] });
    }
    if (choice.forge) steps.push({ id: "forge", label: "Selkies Forge", state: "waiting", lines: [] });
    const job = { state: "running", started: Date.now(), steps };
    this.job = job;
    this.settings.set({ pack: { decided: true, skipped: false, at: Date.now(), chose: steps.map((s) => s.id) } });
    const step = (id) => steps.find((s) => s.id === id);
    const say = (s, line) => { s.lines.push(String(line).replace(ANSI, "").slice(0, 300)); if (s.lines.length > 200) s.lines.shift(); };

    (async () => {
      // Burrow: a switch, nothing to download
      const b = step("burrow");
      b.state = "running";
      this.settings.set({ modules: { ...(this.settings.get("modules") || {}), burrow } });
      say(b, burrow ? "Burrow is on: Tunnels are on the home page." : "Burrow is off. Turn it on any time under Settings → Modules.");
      b.state = "done";

      if (linkTermix) {
        const t = step("termix");
        this.settings.set({ termix: { upstream: linkTermix.upstream } });
        say(t, `linked the Termix on port ${linkTermix.port} (${linkTermix.how}); use your Termix account`);
        t.state = "done";
      }
      if (termix) {
        const t = step("termix");
        t.state = "running";
        try {
          if (!this.settings.get("termix")) {
            say(t, "installing Termix in Docker…");
            this.termix.install();
            while (this.termix.job?.state === "running") {
              await new Promise((r) => setTimeout(r, 1000));
              const last = this.termix.job.lines.slice(-1)[0];
              if (last && t.lines.slice(-1)[0] !== last) say(t, last);
            }
            if (this.termix.job?.state === "error") throw new Error(this.termix.job.error);
          } else say(t, "Termix is already set up.");
          say(t, `creating the Termix account "${termix.username}"…`);
          const r = await this.termix.createUser(termix.username, termix.password);
          say(t, r.existed ? `the account "${termix.username}" already exists; kept it.` : `account "${termix.username}" created. It is Termix's admin.`);
          t.state = "done";
        } catch (e) { t.state = "error"; t.error = e.message; say(t, e.message); }
      }

      if (choice.forge) {
        const f = step("forge");
        f.state = "running";
        if (forgeInstalled()) { say(f, "Selkies Forge is already installed."); f.state = "done"; }
        else {
          say(f, "running the Selkies Forge installer (unattended)…");
          const code = await new Promise((resolve) => {
            const p = spawn("bash", ["-c", `curl -fsSL ${FORGE_INSTALL} | bash -s -- --yes --bg`],
                            { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1", TERM: "dumb" } });
            const feed = (d) => { for (const l of String(d).split("\n")) if (l.trim()) say(f, l); };
            p.stdout.on("data", feed); p.stderr.on("data", feed);
            p.on("error", (e) => { say(f, e.message); resolve(1); });
            p.on("exit", resolve);
          });
          if (code === 0 && forgeInstalled()) { f.state = "done"; say(f, "Selkies Forge is installed; its card appears on the home page when its web UI runs."); }
          else { f.state = "error"; f.error = `the installer exited with ${code}`; }
        }
      }
      job.state = steps.some((s) => s.state === "error") ? "partial" : "done";
      job.finished = Date.now();
      this.log("pack:", job.state, steps.map((s) => `${s.id}=${s.state}`).join(" "));
    })().catch((e) => { job.state = "error"; job.error = e.message; });
    return this.status();
  }
}
