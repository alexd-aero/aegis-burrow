// bin/cli.mjs: the data side of bin/aegis. It talks to the running server over
// data/control.sock (mode 600: this user only) and draws what bash shouldn't:
// the status block, menus' rows, live progress for the pack, the domain and
// updates. bin/aegis stays in charge of questions and menus (bin/ui.sh).
//
//   node cli.mjs call METHOD PATH [JSON]    the raw API; prints the JSON body
//   node cli.mjs status                     the status block
//   node cli.mjs vars                       shell variables for the home menu
//   node cli.mjs get KEY < json             one value (a.b.c) from JSON on stdin
//   node cli.mjs tunnels | ports            menu rows: value<TAB>label<TAB>hint
//   node cli.mjs pack-wait                  follow the pack until it is done
//   node cli.mjs cf-wait                    wait for the Cloudflare authorization
//   node cli.mjs update-wait VERSION        wait for the new version to answer
//
// AEGIS_HOME says where data/control.sock is.
import { request } from "node:http";
import { realpathSync } from "node:fs";
import { join } from "node:path";

const HOME = process.env.AEGIS_HOME || join(process.env.HOME, ".local/share/aegis");
const SOCK = join(HOME, "data", "control.sock");
const C = process.env.AEGIS_COLOR === "1";
const c = (code, s) => (C ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const dim = (s) => c("2", s), bold = (s) => c("1;38;5;255", s), mint = (s) => c("1;38;5;122", s);
const green = (s) => c("38;5;79", s), yellow = (s) => c("38;5;221", s), red = (s) => c("38;5;203", s), violet = (s) => c("38;5;141", s);
const out = (s = "") => process.stdout.write(s + "\n");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function call(method, path, body, timeout = 120000) {
  return new Promise((resolve, reject) => {
    let sock;
    try { sock = realpathSync(SOCK); } catch { return reject(Object.assign(new Error("Aegis × Burrow isn't running (no control socket). Start it: aegis start"), { code: "DOWN" })); }
    const r = request({ socketPath: sock, method, path, timeout,
                        headers: { "Content-Type": "application/json", "X-Burrow-Client": "cli" } }, (res) => {
      let d = "";
      res.on("data", (x) => (d += x));
      res.on("end", () => {
        let j = {};
        try { j = JSON.parse(d || "{}"); } catch { /* not JSON */ }
        if (res.statusCode >= 400) reject(Object.assign(new Error(j.error || `HTTP ${res.statusCode}`), { status: res.statusCode }));
        else resolve(j);
      });
    });
    r.on("timeout", () => r.destroy(new Error("Aegis took too long to answer")));
    r.on("error", (e) => reject(Object.assign(new Error(e.code === "ECONNREFUSED" || e.code === "ENOENT" ? "Aegis × Burrow isn't running. Start it: aegis start" : e.message), { code: "DOWN" })));
    r.end(body ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined);
  });
}

const dur = (ms) => {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : s < 86400 ? `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m` : `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
};
const ago = (t) => (t ? `${dur(Date.now() - t)} ago` : "never");
const row = (k, dot, text) => out(`  ${dim(k.padEnd(9))} ${dot}  ${text}`);
const short = (u) => String(u || "").replace(/^https?:\/\//, "").replace(/\/$/, "");
const ON = () => green("●"), OFF = () => dim("○"), WARN = () => yellow("!");

async function status() {
  let o;
  try { o = await call("GET", "/overview", null, 8000); }
  catch (e) {
    out(); out("  " + bold("Status")); out("  " + dim("─".repeat(64)));
    row("Gate", OFF(), e.code === "DOWN" ? "not running" : red(e.message));
    out("  " + dim("─".repeat(64)));
    return 3;
  }
  out(); out("  " + bold("Status")); out("  " + dim("─".repeat(64)));
  row("Gate", ON(), `running at ${mint(o.mainHost ? "https://" + o.mainHost : o.local)}  ${dim("· v" + o.version + " · up " + dur(Date.now() - o.started))}`);
  if (o.setup) row("Login", WARN(), yellow(o.setupOpen ? "not created yet: aegis setup (or the setup link)" : "not created yet: aegis setup"));
  else row("Login", ON(), `${o.user}  ${dim("· one login for the dashboard, Termix and tunnels")}`);
  if (o.mainHost) row("Local", dim("·"), short(o.local));
  if (o.domain) row("Domain", ON(), `${o.domain.mainHost}  ${dim(o.domain.managed ? "· Aegis runs its cloudflared" : "· through your own cloudflared")}`);
  else row("Domain", OFF(), `none yet ${dim("· aegis domain link")}`);
  const sv = o.serveo || {};
  if (sv.url) row("Serveo", ON(), `${short(sv.url)}${o.mainHost ? dim("  · forwards to the domain") : ""}`);
  else if (sv.on) row("Serveo", WARN(), sv.error ? yellow(String(sv.error).slice(0, 60)) : "connecting…");
  const b = o.burrow || {};
  if (b.on) row("Burrow", b.enabled ? ON() : OFF(), `${b.tunnels} tunnel${b.tunnels === 1 ? "" : "s"} (${b.enabled} live) ${dim("· " + (b.mode === "domain" ? "on " + (o.domain?.zone || "your domain") : "random trycloudflare.com names"))}`);
  else row("Burrow", OFF(), `switched off ${dim("· aegis burrow on")}`);
  if (o.termix) row("Termix", ON(), `${short(o.termix.upstream)} ${dim(o.termix.container ? "· container " + o.termix.container : "· linked")}`);
  if (o.forge) row("Forge", o.forge.linked ? ON() : OFF(), `Selkies Forge ${o.forge.version}${o.forge.linked ? dim(" · linked as addons both ways") : dim(" · on this machine, not linked")}`);
  const u = o.update || {};
  if (u.available) row("Update", violet("✦"), `${mint("v" + u.latest)} is available ${dim("· aegis update")}${u.auto ? dim(" · installs by itself") : ""}`);
  else if (u.checked) row("Update", ON(), `up to date ${dim("· checked " + ago(u.checked) + (u.auto ? " · auto-update on" : ""))}`);
  out("  " + dim("─".repeat(64)));
  return 0;
}

// shell variables for the home menu (values are quoted, single quotes dropped)
async function vars() {
  const q = (v) => `'${String(v ?? "").replace(/'/g, "")}'`;
  let o;
  try { o = await call("GET", "/overview", null, 8000); } catch { out("UP=0"); return; }
  const lines = {
    UP: 1, SETUP: o.setup ? 1 : 0, USER_NAME: o.user || "", DASH: o.mainHost ? `https://${o.mainHost}/` : o.local, LOCAL: o.local,
    SERVEO: o.serveo?.url ? o.serveo.url + "/" : "", SERVEO_ON: o.serveo?.wanted ? 1 : 0,
    DOMAIN: o.domain?.mainHost || "", DOMAIN_MANAGED: o.domain?.managed ? 1 : 0, BURROW_ON: o.burrow?.on ? 1 : 0, TUNNELS: o.burrow?.tunnels || 0,
    TERMIX: o.termix ? 1 : 0, FORGE: o.forge ? 1 : 0, UPD: o.update?.available ? 1 : 0, UPD_TO: o.update?.latest || "", AUTO_UPD: o.update?.auto ? 1 : 0,
    PACK_DECIDED: o.pack?.decided ? 1 : 0, VERSION: o.version,
  };
  for (const [k, v] of Object.entries(lines)) out(`${k}=${q(v)}`);
}

async function tunnels() {
  const j = await call("GET", "/tunnels");
  for (const t of j.tunnels) {
    const state = !t.enabled ? "paused" : t.health?.up === false ? "target down" : "live";
    out(`${t.port}\t${t.port}  ${t.name || t.title || "tunnel-" + t.port}\t${state} · ${t.access === "public" ? "public" : "login"} · ${short(t.url) || "address on its way"}`);
  }
}
async function ports() {
  const j = await call("GET", "/ports");
  for (const p of j.ports.filter((x) => !x.tunneled).slice(0, 40)) {
    const bind = p.addrs.find((a) => !["0.0.0.0", "::", "*", "::1"].includes(a) && !a.startsWith("127."));
    out(`${p.port}:${p.local ? "127.0.0.1" : bind || "127.0.0.1"}\t${p.port}\t${p.process || "listening"}${p.local ? "" : " · on " + bind}`);
  }
}

// follow the pack: one line per step, its last log line under it
async function packWait() {
  let shown = 0, last = "";
  for (;;) {
    let s;
    try { s = await call("GET", "/pack", null, 30000); } catch (e) { out(red("  ✘ " + e.message)); return 1; }
    const j = s.job;
    if (!j) return 0;
    const lines = j.steps.map((st) => {
      const ic = st.state === "done" ? green("✔") : st.state === "error" ? red("✘") : st.state === "running" ? mint("◌") : dim("○");
      const tail = st.error || st.lines[st.lines.length - 1] || "";
      return `  ${ic} ${st.state === "waiting" ? dim(st.label) : st.label}${tail ? "\n      " + dim(String(tail).slice(0, 90)) : ""}`;
    }).join("\n");
    if (lines !== last) {
      if (shown && process.stdout.isTTY) process.stdout.write(`\x1b[${shown}A\x1b[J`);
      out(lines);
      shown = lines.split("\n").length;
      last = lines;
    }
    if (j.state !== "running") return j.state === "done" ? 0 : 1;
    await sleep(1200);
  }
}

async function cfWait() {
  const t0 = Date.now();
  for (;;) {
    let s;
    try { s = await call("GET", "/cf", null, 15000); } catch (e) { out(e.message); return 1; }
    if (s.cert || s.domain) { out(s.cert?.zone?.name || s.domain?.zone || ""); return 0; }
    if (s.login && !s.login.waiting && s.login.error) { process.stderr.write(s.login.error + "\n"); return 1; }
    if (!s.login) { process.stderr.write("Cancelled.\n"); return 1; }
    if (Date.now() - t0 > 15 * 60000) { process.stderr.write("No authorization after 15 minutes.\n"); return 1; }
    await sleep(2000);
  }
}

// after an update the server restarts: wait until the socket answers with the new version
async function updateWait(want) {
  const t0 = Date.now();
  await sleep(1500);
  for (;;) {
    try { const s = await call("GET", "/status", null, 3000); if (s.version === want) return 0; } catch { /* restarting */ }
    if (Date.now() - t0 > 120000) return 1;
    await sleep(1000);
  }
}

// the update waiting, release by release (from GET /update)
async function whatsNew() {
  const u = await call("GET", "/update", null, 8000);
  for (const e of (u.entries || []).slice(0, 8)) {
    out(`    ${green("●")} ${e.version ? mint(("v" + e.version).padEnd(8)) : dim(e.short.padEnd(8))} ${e.title}`);
  }
  if (!(u.entries || []).length) out(`    ${dim("(no release notes; see " + u.repo + "/commits)")}`);
  out(`    ${dim("○")} ${dim(("v" + u.current).padEnd(8))} ${dim("the version you have")}`);
  return 0;
}

function get(key) {
  let d = "";
  process.stdin.on("data", (x) => (d += x));
  process.stdin.on("end", () => {
    let v;
    try { v = JSON.parse(d || "{}"); } catch { v = {}; }
    for (const k of key.split(".")) v = v == null ? undefined : v[k];
    process.stdout.write(v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
  });
}

const [cmd, ...args] = process.argv.slice(2);
const run = {
  // on failure the message goes to stdout too: bash reads it with out="$(…)" || die "$out"
  // JSON "-" is read from stdin, so passwords never show up in `ps`
  call: async () => {
    let body = args[2] || null;
    if (body === "-") { body = ""; for await (const x of process.stdin) body += x; }
    try { out(JSON.stringify(await call(args[0], args[1], body))); return 0; } catch (e) { out(e.message); return e.code === "DOWN" ? 3 : 2; }
  },
  "whats-new": whatsNew,
  status, vars: async () => { await vars(); return 0; },
  tunnels: async () => { await tunnels(); return 0; }, ports: async () => { await ports(); return 0; },
  "pack-wait": packWait, "cf-wait": cfWait, "update-wait": () => updateWait(args[0]),
  get: () => { get(args[0]); return null; },
}[cmd];
if (!run) { process.stderr.write("cli.mjs: unknown command\n"); process.exit(2); }
Promise.resolve(run()).then((code) => { if (code != null) process.exit(code); },
  (e) => { process.stderr.write((e && e.message) + "\n"); process.exit(e && e.code === "DOWN" ? 3 : 2); });
