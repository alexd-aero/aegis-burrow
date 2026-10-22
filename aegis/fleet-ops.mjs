// What machine management actually does on the machines: install an app,
// move an app and its data from one to the other, add a machine to Termix,
// and keep a clone of this gate on another machine that takes over if this
// host goes down.
//
// Every one of these runs as a job (aegis/fleet.mjs): a phase, a progress
// bar and the far side's own output, polled by the dashboard.
//
// Nothing here is silent. An install runs the project's own published
// installer; a swap stops both apps, keeps the old data beside the new one
// and starts them again; the standby clone leaves this machine's fleet key
// behind (a clone that could reach every other machine is not a backup, it
// is a second key).

import { spawn } from "node:child_process";
import { appendFileSync, createWriteStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hostname, networkInterfaces, userInfo } from "node:os";
import { randomBytes } from "node:crypto";
import { HOME, DATA, readJson, writeJson } from "./config.mjs";
import { FleetError, run, sq } from "./fleet.mjs";

const fail = (m) => { throw new FleetError(m); };

// ------------------------------------------------------------------ the apps
// install: the project's own one-line installer, run on the far machine.
// data:    what a swap carries over, found on the machine itself.
// service: how it is stopped and started again.
export const CATALOG = {
  "aegis-burrow": {
    name: "Aegis \u00d7 Burrow",
    install: "curl -fsSL https://raw.githubusercontent.com/alexd-aero/aegis-burrow/main/install.sh | bash",
    note: "Installs the gate itself, with its own login and its own first-run setup.",
    locate: `cfg="$HOME/.config/aegis/aegis.json"
[ -r "$cfg" ] || exit 0
sed -n 's/.*"home": *"\\([^"]*\\)".*/data=\\1/p' "$cfg" | head -1
sed -n 's/.*"name": *"\\([^"]*\\)".*/unit=\\1/p' "$cfg" | head -1`,
    swappable: false,                  // its data is the login and the tunnels: moving it is a takeover, not a swap
  },
  "selkies-forge": {
    name: "Selkies Forge",
    install: "curl -fsSL https://raw.githubusercontent.com/adatskov-wcpss/animated-fiesta/main/docker.sh | bash",
    note: "Needs Docker; its installer offers to add it.",
    locate: `[ -d "$HOME/.selkies-forge" ] || exit 0
echo "data=$HOME/.selkies-forge"
echo unit=selkies-forge.service`,
    swappable: true,
  },
  termix: {
    name: "Termix",
    install: `set -e
command -v docker >/dev/null || { echo "Docker is not installed on this machine." >&2; exit 1; }
port=4300; while docker ps --format '{{.Ports}}' | grep -q ":$port->" ; do port=$((port+1)); done
docker pull ghcr.io/lukegus/termix:latest
docker rm -f aegis-termix >/dev/null 2>&1 || true
docker run -d --name aegis-termix --restart unless-stopped -p 127.0.0.1:$port:8080 -e PORT=8080 \\
  -v aegis-termix-data:/app/data --label io.aegis.app=termix ghcr.io/lukegus/termix:latest
echo "Termix is on 127.0.0.1:$port of that machine. Publish that port with a tunnel to reach it."`,
    note: "One Docker container, bound to that machine's loopback only.",
    locate: `c=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Ex '(aegis-)?termix' | head -1)
[ -n "$c" ] || exit 0
v=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Name}}{{end}}{{end}}' "$c" 2>/dev/null)
[ -n "$v" ] || exit 0
echo "volume=$v"
echo "container=$c"`,
    swappable: true,
  },
  bulwark: {
    name: "Bulwark",
    install: null,                      // it rides along with Aegis x Burrow as a default addon
    note: "Bulwark installs itself with Aegis \u00d7 Burrow, as its shield addon.",
    locate: `[ -d "$HOME/.local/share/bulwark" ] || exit 0
echo "data=$HOME/.local/share/bulwark"
echo unit=bulwark.service`,
    swappable: true,
  },
};

// Stop and start, whichever way the machine runs things. Defined once and
// pasted into the scripts below.
export const HELPERS = `
svc() {   # svc stop|start UNIT
  act=$1; unit=$2
  [ -n "$unit" ] || return 0
  if systemctl --user list-unit-files 2>/dev/null | grep -q "^$unit"; then systemctl --user "$act" "$unit" 2>/dev/null && { echo "  systemctl --user $act $unit"; return 0; }; fi
  if systemctl list-unit-files 2>/dev/null | grep -q "^$unit"; then
    if [ "$(id -u)" = 0 ]; then systemctl "$act" "$unit" 2>/dev/null && { echo "  systemctl $act $unit"; return 0; }
    elif sudo -n true 2>/dev/null; then sudo systemctl "$act" "$unit" 2>/dev/null && { echo "  sudo systemctl $act $unit"; return 0; }; fi
  fi
  echo "  no service called $unit here"
  return 1
}
`;

// ------------------------------------------------------------------ installing
// programs: what installed addons bring (server.mjs addonPrograms): id ->
// { name, note, addon, install(machine, tools) }. An addon's program does its
// own work through tools.run (a script, over this Fleet's link); Fleet then
// leaves a note on the machine so the next look sees it is there.
export function install(fleet, id, appId, programs = new Map()) {
  const m = fleet.get(id);
  if (!CATALOG[appId] && programs.has(appId)) return installProgram(fleet, m, appId, programs.get(appId));
  const app = CATALOG[appId];
  if (!app) fail("Aegis does not know how to install that.");
  if (!app.install) fail(app.note);
  return fleet.start("install", `Installing ${app.name} on ${m.name}`, id, async (job) => {
    job.step(`Installing ${app.name} on ${m.name}`, 0.1);
    job.log(app.note, "muted");
    const r = await fleet.ssh(m, `set -o pipefail 2>/dev/null || true\n${app.install}\n`,
                              { timeout: 30 * 60000, onLine: (l) => job.log(l) });
    if (r.code !== 0) fail(`the installer failed on ${m.name} (exit ${r.code}): ${(r.err || r.out).split("\n").filter(Boolean).pop() || "no output"}`);
    job.step("Looking at what it left behind", 0.9);
    await fleet.probe(id, { fresh: true }).catch(() => {});
    return { app: appId, machine: id };
  });
}

function installProgram(fleet, m, appId, p) {
  return fleet.start("install", `Installing ${p.name} on ${m.name}`, m.id, async (job) => {
    job.step(`Installing ${p.name} on ${m.name}`, 0.1);
    if (p.note) job.log(p.note, "muted");
    const tools = {
      run: (script, { timeout = 10 * 60000 } = {}) => fleet.ssh(m, String(script), { timeout, onLine: (l) => job.log(l) }),
      log: (line, cls) => job.log(line, cls),
      step: (phase, progress) => job.step(phase, progress),
    };
    const machine = { id: m.id, name: m.name, address: m.address, user: m.user, port: m.port, hostname: m.probe?.host?.hostname || null,
                      addresses: [...(m.probe?.addresses || [])] };
    const res = (await p.install(machine, tools)) || {};
    job.step("Noting it on the machine", 0.92);
    const note = JSON.stringify({ id: appId, name: p.name, addon: p.addon, version: res.version || null, url: res.url || null, at: Date.now() });
    const file = `$HOME/.config/aegis/programs/${appId.replace(/[^a-z0-9._-]/gi, "_")}.json`;
    await fleet.ssh(m, `mkdir -p "$HOME/.config/aegis/programs" && printf '%s\\n' ${sq(note)} > "${file}"\n`, { timeout: 30000 });
    await fleet.probe(m.id, { fresh: true }).catch(() => {});
    return { app: appId, machine: m.id, ...(res.url ? { url: res.url } : {}) };
  });
}

// ------------------------------------------------------------------ swapping
// Selkies Forge on A and the one on B change places, data and all. The old
// data is not deleted: it is moved aside on each machine first.
export function swap(fleet, appId, idA, idB) {
  const app = CATALOG[appId];
  if (!app) fail("Aegis does not know that app.");
  if (!app.swappable) fail(`${app.name} cannot be swapped: ${app.note}`);
  if (idA === idB) fail("Pick two different machines.");
  const A = fleet.get(idA), B = fleet.get(idB);
  const dir = join(fleet.dir, "swap");
  return fleet.start("swap", `Swapping ${app.name} between ${A.name} and ${B.name}`, `${idA}+${idB}`, async (job) => {
    const tag = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const tars = { [idA]: join(dir, `${appId}-${idA}-${tag}.tgz`), [idB]: join(dir, `${appId}-${idB}-${tag}.tgz`) };
    await run("mkdir", ["-p", dir]);
    try {
      job.step(`Finding ${app.name} on both machines`, 0.05);
      const where = {};
      for (const m of [A, B]) {
        where[m.id] = await locate(fleet, m, app);
        job.log(`${m.name}: ${where[m.id].kind === "volume" ? `docker volume ${where[m.id].path}` : where[m.id].path}`);
      }
      job.step("Stopping it on both machines", 0.15);
      for (const m of [A, B]) {
        job.log(`${m.name}:`);
        await stopApp(fleet, m, app, where[m.id], job);
      }

      job.step("Packing each machine's data", 0.3);
      for (const m of [A, B]) {
        await pull(fleet, m, where[m.id], tars[m.id], job);
        job.log(`${m.name}: ${(statSync(tars[m.id]).size / 1e6).toFixed(1)} MB packed`);
      }
      job.step("Putting each machine's data on the other", 0.6);
      await push(fleet, A, where[idA], tars[idB], tag, job);
      await push(fleet, B, where[idB], tars[idA], tag, job);

      job.step("Starting it again", 0.85);
      for (const m of [A, B]) {
        job.log(`${m.name}:`);
        await startApp(fleet, m, app, where[m.id], job);
      }
      for (const m of [A, B]) await fleet.probe(m.id, { fresh: true }).catch(() => {});
      job.log("Neither machine's old data was deleted: each is kept beside the new one, with this swap's stamp on the end.", "muted");
      return { app: appId, a: idA, b: idB, tag };
    } finally {
      for (const f of Object.values(tars)) { try { rmSync(f, { force: true }); } catch { /* gone */ } }
    }
  });
}

// ------------------------------------------------------------------ moving
// One app and its data from machine A to machine B, one way. "copy" leaves A
// running as it was; "move" stops A and keeps it from starting by itself
// (its data stays where it was - nothing is deleted). B gets the app first
// if it doesn't have it, and whatever B had is moved aside, never deleted.
export function transfer(fleet, appId, fromId, toId, { mode = "copy", programs = new Map() } = {}) {
  const app = CATALOG[appId];
  if (!app) fail("Aegis does not know that app.");
  if (!app.swappable) fail(`${app.name} cannot be moved: ${app.note}`);
  if (fromId === toId) fail("Pick two different machines.");
  if (!["move", "copy"].includes(mode)) fail("A transfer is a move or a copy.");
  const A = fleet.get(fromId), B = fleet.get(toId);
  const dir = join(fleet.dir, "swap");
  const verb = mode === "move" ? "Moving" : "Copying";
  return fleet.start("transfer", `${verb} ${app.name} from ${A.name} to ${B.name}`, `${fromId}+${toId}`, async (job) => {
    const tag = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const tar = join(dir, `${appId}-${fromId}-${tag}.tgz`);
    await run("mkdir", ["-p", dir]);
    try {
      job.step(`Finding ${app.name} on ${A.name}`, 0.05);
      const from = await locate(fleet, A, app);
      job.log(`${A.name}: ${from.kind === "volume" ? `docker volume ${from.path}` : from.path}`);

      job.step(`Making sure ${B.name} has ${app.name}`, 0.12);
      let to = await locate(fleet, B, app).catch(() => null);
      if (!to) {
        if (!app.install) fail(`${app.name} is not on ${B.name}, and Aegis cannot install it there: ${app.note}`);
        job.log(`${B.name} does not have it yet: installing it first.`);
        const r = await fleet.ssh(B, `set -o pipefail 2>/dev/null || true\n${app.install}\n`, { timeout: 30 * 60000, onLine: (l) => job.log(`  ${l}`) });
        if (r.code !== 0) fail(`installing ${app.name} on ${B.name} failed (exit ${r.code})`);
        to = await locate(fleet, B, app);
      }
      job.log(`${B.name}: ${to.kind === "volume" ? `docker volume ${to.path}` : to.path}`);

      job.step(`Stopping it on ${A.name} so its data is still`, 0.25);
      job.log(`${A.name}:`);
      await stopApp(fleet, A, app, from, job);
      try {
        job.step(`Packing ${A.name}'s data`, 0.35);
        await pull(fleet, A, from, tar, job);
        job.log(`  ${(statSync(tar).size / 1e6).toFixed(1)} MB packed`);
      } finally {
        if (mode === "copy") { job.log(`${A.name}: starting it again (a copy leaves it running)`); await startApp(fleet, A, app, from, job).catch((e) => job.log(`  ${e.message}`, "err")); }
      }

      job.step(`Putting it on ${B.name}`, 0.6);
      job.log(`${B.name}:`);
      await stopApp(fleet, B, app, to, job);
      await push(fleet, B, to, tar, tag, job);
      job.step(`Starting it on ${B.name}`, 0.85);
      await startApp(fleet, B, app, to, job);

      if (mode === "move") {
        job.step(`Keeping ${A.name}'s copy from starting by itself`, 0.92);
        const r = await fleet.ssh(A, from.kind === "volume"
          ? `docker update --restart=no ${sq(from.container || "aegis-termix")} >/dev/null 2>&1 && echo "  the container ${from.container || "aegis-termix"} no longer starts by itself" || true`
          : `${HELPERS}\nunit=${sq(from.unit || "")}\n[ -n "$unit" ] && { systemctl --user disable "$unit" 2>/dev/null || sudo -n systemctl disable "$unit" 2>/dev/null; } && echo "  $unit no longer starts at boot" || true`, { timeout: 60000 });
        job.log(r.out || "  nothing to change");
        job.log(`${A.name}'s data is still there, untouched: to go back, transfer it the other way.`, "muted");
      }
      for (const m of [A, B]) await fleet.probe(m.id, { fresh: true }).catch(() => {});
      return { app: appId, from: fromId, to: toId, mode, tag };
    } finally {
      try { rmSync(tar, { force: true }); } catch { /* gone */ }
    }
  });
}

// Where the app keeps its data on that machine, and what runs it: a folder
// and a service unit, or a Docker volume and its container.
async function locate(fleet, m, app) {
  const r = await fleet.ssh(m, app.locate, { timeout: 25000 });
  const read = (k) => { const x = new RegExp(`(^|\\n)${k}=(.+)`).exec(r.out); return x ? x[2].trim() : null; };
  const vol = read("volume"), data = read("data");
  if (vol) return { kind: "volume", path: vol, container: read("container") };
  if (data) return { kind: "dir", path: data, unit: read("unit") };
  fail(`${app.name} is not on ${m.name}.`);
}
async function stopApp(fleet, m, app, where, job) {
  if (where.kind === "volume") {
    const c = where.container || "aegis-termix";
    const r = await fleet.ssh(m, `docker stop ${sq(c)} >/dev/null 2>&1 && echo "  stopped the container ${c}" || echo "  no container called ${c} is running"`, { timeout: 90000 });
    return job.log(r.out);
  }
  const r = await fleet.ssh(m, `${HELPERS}\nsvc stop ${sq(where.unit || "")} || true`, { timeout: 90000 });
  job.log(r.out || "  nothing to stop");
}
async function startApp(fleet, m, app, where, job) {
  if (where.kind === "volume") {
    const c = where.container || "aegis-termix";
    const r = await fleet.ssh(m, `docker start ${sq(c)} >/dev/null 2>&1 && echo "  started the container ${c}" || echo "  could not start ${c}"`, { timeout: 90000 });
    return job.log(r.out);
  }
  const r = await fleet.ssh(m, `${HELPERS}\nsvc start ${sq(where.unit || "")} || true`, { timeout: 90000 });
  job.log(r.out || "  nothing to start");
}

// Stream a tar of that machine's data here. Nothing is written on the far side.
async function pull(fleet, m, where, outFile, job) {
  const script = where.kind === "volume"
    ? `docker run --rm -v ${sq(where.path)}:/d:ro busybox tar -C /d -cf - .`
    : `tar -C ${sq(where.path)} -cf - .`;
  const out = createWriteStream(outFile, { mode: 0o600 });
  const code = await new Promise((resolve) => {
    const p = spawn("ssh", [...fleet.sshArgs(m), "--", "bash -s"], { stdio: ["pipe", "pipe", "pipe"] });
    p.stdout.pipe(out);
    let err = "";
    p.stderr.on("data", (c) => { err += c; });
    const t = setTimeout(() => { try { p.kill("SIGKILL"); } catch { /* gone */ } }, 20 * 60000);
    p.on("error", () => { clearTimeout(t); resolve(127); });
    p.on("close", (c) => {
      clearTimeout(t);
      for (const l of err.split("\n").filter(Boolean).slice(-4)) job.log(`  ${l}`, "muted");
      resolve(c ?? 1);
    });
    p.stdin.end(script);
  });
  await new Promise((r2) => out.end(r2));
  if (code !== 0 || !existsSync(outFile) || statSync(outFile).size < 64) fail(`could not read ${m.name}'s data (exit ${code})`);
}

// Put the other machine's tar in place. What was there is moved aside first,
// never deleted.
async function push(fleet, m, where, tarFile, tag, job) {
  const remote = `/tmp/aegis-swap-${randomBytes(4).toString("hex")}.tar`;
  await fleet.copyTo(m, tarFile, remote, 20 * 60000);
  const script = where.kind === "volume"
    ? `set -eu
keep="$HOME/aegis-swap-${tag}-${where.path}.tar"
docker run --rm -v ${sq(where.path)}:/d:ro -v "$HOME":/b busybox tar -C /d -cf "/b/$(basename "$keep")" .
docker run --rm -v ${sq(where.path)}:/d -v ${sq(remote)}:/in.tar:ro busybox sh -c 'rm -rf /d/..?* /d/.[!.]* /d/*; tar -C /d -xf /in.tar'
rm -f ${sq(remote)}
echo "  restored into the volume ${where.path} (what was there is kept as $keep)"`
    : `set -eu
d=${sq(where.path)}
mv "$d" "$d.before-${tag}"
mkdir -p "$d"
tar -C "$d" -xf ${sq(remote)}
rm -f ${sq(remote)}
echo "  restored into $d (what was there is kept as $d.before-${tag})"`;
  const r = await fleet.ssh(m, script, { timeout: 15 * 60000 });
  if (r.code !== 0) fail(`could not write ${m.name}'s data: ${(r.err || r.out).split("\n").filter(Boolean).pop()}`);
  job.log(r.out);
}

// ------------------------------------------------------------------ Termix
// Add a machine to Termix as a host: its address, its SSH port, and either
// the fleet key (what Aegis itself uses) or a password you type. Only ever
// with your say-so, and Termix's own login is asked for each time; Aegis
// does not keep it.
export async function toTermix(fleet, termix, id, { username, password, auth = "key", hostPassword, folder = "Aegis" }) {
  const m = fleet.get(id);
  const t = termix.config();
  if (!t?.upstream) fail("Termix is not set up on this machine.");
  if (!username || !password) fail("Termix needs its own user name and password to add a host.");
  const base = t.upstream.replace(/\/+$/, "");
  const jar = { jwt: null };
  const call = async (path, opts = {}) => {
    const r = await fetch(base + path, {
      ...opts,
      headers: { "Content-Type": "application/json", ...(jar.jwt ? { Authorization: `Bearer ${jar.jwt}`, Cookie: `jwt=${jar.jwt}` } : {}), ...(opts.headers || {}) },
      signal: AbortSignal.timeout(15000),
    });
    const set = r.headers.get("set-cookie") || "";
    const got = /(?:^|[,;\s])jwt=([^;,\s]+)/.exec(set);
    if (got) jar.jwt = got[1];
    const j = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, j };
  };

  const login = await call("/users/login", { method: "POST", body: JSON.stringify({ username, password }) });
  if (!login.ok) fail(login.j.error || `Termix refused that login (HTTP ${login.status}).`);
  if (login.j.requires_totp || login.j.requires_second_factor) fail("That Termix account asks for a second factor; add the host in Termix itself.");
  if (!jar.jwt && login.j.token) jar.jwt = login.j.token;
  if (!jar.jwt) fail("Termix did not hand back a session.");

  const status = await call("/users/data-status");
  if (status.ok && status.j.unlocked === false) {
    const un = await call("/users/unlock-data", { method: "POST", body: JSON.stringify({ password }) });
    if (!un.ok) fail(un.j.error || "Termix could not unlock its data with that password.");
  }

  const list = await call("/ssh/db/host");
  const already = Array.isArray(list.j) ? list.j.find((hst) => hst.ip === m.address && Number(hst.port) === Number(m.port) && hst.username === m.user) : null;
  if (already) {
    fleet.patch(id, { termix: { at: Date.now(), hostId: already.id ?? null, auth: already.authType || null } });
    return { ok: true, existed: true, id: already.id, name: already.name || m.name, upstream: t.upstream };
  }

  const body = {
    name: m.name, ip: m.address, port: m.port, username: m.user, folder,
    tags: ["aegis", "fleet"], pin: false, enableTerminal: true, enableFileManager: true, enableTunnel: false,
    authType: auth === "password" ? "password" : "key",
    ...(auth === "password"
      ? { password: String(hostPassword || "") }
      : { key: readFileSync(fleet.keyPath(), "utf8"), keyType: "ssh-ed25519", keyPassword: "" }),
  };
  if (auth === "password" && !body.password) fail("No password was given for that machine.");
  const made = await call("/ssh/db/host", { method: "POST", body: JSON.stringify(body) });
  if (!made.ok) fail(made.j.error || `Termix would not add the host (HTTP ${made.status}).`);
  fleet.patch(id, { termix: { at: Date.now(), hostId: made.j.hostId || made.j.id || null, auth: body.authType } });
  return { ok: true, existed: false, id: made.j.hostId || made.j.id || null, name: m.name, upstream: t.upstream };
}

// ------------------------------------------------------------------ moving this gate
// This whole gate - login, domain, tunnels, addons, machines, settings - onto
// a linked machine, which then *is* the gate. In order:
//
//   1. refuse what can't move (a domain whose tunnel is run by a cloudflared
//      service outside Aegis would keep sending its traffic here)
//   2. the machine gets Aegis × Burrow (its own installer, --no-start), or the
//      Aegis it already has is stopped and its config/data put aside
//   3. this gate's config.json, secret.key and data/ go over; paths under this
//      home are rewritten to that one; the target is dropped from its machines
//      and this machine is added in its place (so the new gate can reach it)
//   4. it starts there; on its first start every installed addon is started
//      "whatever it takes" (burrow/rescue.mjs), which installs Bulwark's
//      service and the like over there
//   5. only once it answers: this gate stands down (settings.moved) - after a
//      restart it serves a notice and nothing else. `aegis resume-here` undoes it.
export function moveGate(fleet, id, { domain, version } = {}) {
  const m = fleet.get(id);
  if (domain && domain.managed === false) {
    fail(`Your domain's tunnel is run by a cloudflared service outside Aegis on this machine, so its traffic would keep arriving here. Link the domain from Aegis itself (Settings → Domain) first, or move that cloudflared service with it.`);
  }
  return fleet.start("move-gate", `Moving this gate to ${m.name}`, id, async (job) => {
    const tag = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    job.step(`Looking at ${m.name}`, 0.04);
    const pre = await fleet.ssh(m, `set -u
cfg="$HOME/.config/aegis/aegis.json"
echo "arch=$(uname -m)"
echo "free=$(df -Pk "$HOME" 2>/dev/null | awk 'NR==2{print $4}')"
command -v curl >/dev/null && echo curl=ok
command -v tar >/dev/null && echo tar=ok
[ -r "$cfg" ] && { echo "have=yes"; sed -n 's/.*"home": *"\\([^"]*\\)".*/home=\\1/p;s/.*"cli": *"\\([^"]*\\)".*/cli=\\1/p' "$cfg"; }
echo "userhome=$HOME"`, { timeout: 30000 });
    const kv = Object.fromEntries(pre.out.split("\n").map((l) => l.split("=")).filter((x) => x.length >= 2).map(([k, ...v]) => [k.trim(), v.join("=").trim()]));
    if (!kv.tar) fail(`${m.name} has no tar.`);
    const size = Number((await run("du", ["-sk", HOME])).out.split(/\s/)[0]) || 0;
    if (Number(kv.free) && Number(kv.free) < size * 2 + 300 * 1024) fail(`${m.name} has ${Math.round(Number(kv.free) / 1024)} MB free; this gate needs about ${Math.round((size * 2) / 1024 + 300)} MB.`);

    let home = kv.home, cli = kv.cli;
    if (kv.have !== "yes" || !home || !cli) {
      if (!kv.curl) fail(`${m.name} has no curl to fetch Aegis × Burrow with.`);
      job.step(`Installing Aegis × Burrow on ${m.name} (its own installer)`, 0.1);
      const r = await fleet.ssh(m, `set -o pipefail; curl -fsSL https://raw.githubusercontent.com/alexd-aero/aegis-burrow/main/install.sh | bash -s -- --no-start </dev/null`,
                                { timeout: 20 * 60000, onLine: (l) => job.log(`  ${l}`) });
      if (r.code !== 0) fail(`the installer failed on ${m.name} (exit ${r.code})`);
      const again = await fleet.ssh(m, `sed -n 's/.*"home": *"\\([^"]*\\)".*/home=\\1/p;s/.*"cli": *"\\([^"]*\\)".*/cli=\\1/p' "$HOME/.config/aegis/aegis.json"`, { timeout: 20000 });
      home = /home=(.+)/.exec(again.out)?.[1]?.trim(); cli = /cli=(.+)/.exec(again.out)?.[1]?.trim();
      if (!home || !cli) fail(`Aegis × Burrow did not say where it lives on ${m.name}.`);
    } else job.log(`${m.name} already has Aegis × Burrow in ${home}: its own config and data are put aside, not deleted.`);

    job.step("Packing this gate", 0.35);
    const tar = join(fleet.dir, `move-${tag}.tgz`);
    // this machine joins the new gate's machines, with the key the gate already uses
    const me = { id: `m-${randomBytes(5).toString("hex")}`, name: hostname(), hostname: hostname(), user: userInfo().username, port: 22,
                 address: localAddrs()[0] || hostname(), candidates: localAddrs(), addedAt: Date.now(), addedFrom: "move", lastSeen: null,
                 lastError: null, standby: false, probe: null, probedAt: null, os: "", arch: "" };
    const t = await run("tar", ["-C", HOME, "--exclude=./data/fleet/swap", "--exclude=./data/fleet/clone-*", "--exclude=./data/fleet/move-*",
                                "--exclude=./data/control.sock", "--exclude=./data/runtime.json", "-czf", tar,
                                ...["config.json", "secret.key", "data"].filter((f) => existsSync(join(HOME, f)))], { timeout: 10 * 60000 });
    if (t.code !== 0) fail(`could not pack this gate: ${t.err.split("\n").pop()}`);
    job.log(`  ${(statSync(tar).size / 1e6).toFixed(1)} MB: config, secret key, data (login, domain, tunnels, addons, machines, certificates)`);
    try {
      const pub = (await fleet.publicKey()).trim();
      job.step(`Copying it to ${m.name}`, 0.45);
      const remote = `/tmp/aegis-move-${randomBytes(4).toString("hex")}.tgz`;
      await fleet.copyTo(m, tar, remote, 20 * 60000);

      job.step(`Putting it in place on ${m.name}`, 0.6);
      const r = await fleet.ssh(m, `set -eu
H=${sq(home)}
"${cli.replace(/"/g, "")}" stop >/dev/null 2>&1 || true
keep="$H/before-move-${tag}"
mkdir -p "$keep"
for f in config.json secret.key data; do [ -e "$H/$f" ] && mv "$H/$f" "$keep/" || true; done
tar -C "$H" -xzf ${sq(remote)}
rm -f ${sq(remote)}
chmod 700 "$H" "$H/data"; chmod 600 "$H/secret.key"
echo "  unpacked into $H (what was there is in $keep)"
node_bin=$(command -v node || echo "$H/node/bin/node")
OLD=${sq(HOME)} NEW="$H" DROP=${sq(id)} ME=${sq(JSON.stringify(me))} FROM=${sq(hostname())} "$node_bin" -e '
  const fs = require("fs"), path = require("path");
  const { OLD, NEW, DROP, ME, FROM } = process.env;
  const walk = (d, n = 0) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name);
    if (e.isDirectory() && n < 3 && e.name !== "addons") walk(p, n + 1);
    else if (e.isFile() && e.name.endsWith(".json")) { const t = fs.readFileSync(p, "utf8"); if (t.includes(OLD)) { fs.writeFileSync(p, t.split(OLD).join(NEW)); console.log("  paths rewritten in " + path.relative(NEW, p)); } } } };
  for (const f of ["config.json"]) { const p = path.join(NEW, f); if (fs.existsSync(p)) { const t = fs.readFileSync(p, "utf8"); if (t.includes(OLD)) fs.writeFileSync(p, t.split(OLD).join(NEW)); } }
  walk(path.join(NEW, "data"));
  const fj = path.join(NEW, "data", "fleet.json");
  if (fs.existsSync(fj)) { const db = JSON.parse(fs.readFileSync(fj, "utf8")); db.machines = (db.machines || []).filter((x) => x.id !== DROP); db.machines.push(JSON.parse(ME)); fs.writeFileSync(fj, JSON.stringify(db)); console.log("  " + FROM + " is now one of its machines"); }
  fs.writeFileSync(path.join(NEW, "data", "moved-in.json"), JSON.stringify({ from: FROM, at: Date.now() }));
'`, { timeout: 5 * 60000 });
      if (r.code !== 0) fail(`putting it in place failed: ${(r.err || r.out).split("\n").filter(Boolean).pop()}`);
      for (const l of r.out.split("\n").filter(Boolean)) job.log(l);

      job.step(`Letting the new gate reach ${hostname()}`, 0.7);
      const ak = join(process.env.HOME || userInfo().homedir, ".ssh", "authorized_keys");
      mkdirSync(dirname2(ak), { recursive: true, mode: 0o700 });
      const had = existsSync(ak) && readFileSync(ak, "utf8").includes(pub);
      if (!had) appendFileSync(ak, `${pub}\n`, { mode: 0o600 });
      job.log(had ? "  its key was already allowed here" : `  its machine key may now sign in here as ${userInfo().username}`);

      job.step(`Starting it on ${m.name}`, 0.8);
      const st = await fleet.ssh(m, `"${cli.replace(/"/g, "")}" start 2>&1 | tail -5`, { timeout: 3 * 60000, onLine: (l) => job.log(`  ${l}`) });
      if (!/started|done|already/i.test(st.out)) fail(`it did not come up on ${m.name}: ${st.out.split("\n").filter(Boolean).pop() || "no answer"}. This gate keeps running; nothing here changed.`);

      job.step("Handing over", 0.95);
      fleet.settings.set({ moved: { to: m.name, address: m.address, machine: id, at: Date.now(), version: version || null } });
      job.log(`${m.name} is the gate now. This one stands down in a few seconds and only shows where it went; \`aegis resume-here\` on this machine undoes that.`, "ok");
      job.log("Addons start themselves there on its first start (their services are installed again if they have to be). Apps that run beside Aegis on this machine - Termix, Selkies Forge - stay here: move them with Move an app.", "muted");
      return { machine: id, home, standDown: true };
    } finally { rmSync(tar, { force: true }); }
  });
}
const dirname2 = (p) => p.slice(0, p.lastIndexOf("/")) || "/";
function localAddrs() {
  const out = [];
  for (const list of Object.values(networkInterfaces())) for (const a of list || []) if (!a.internal && a.family === "IPv4") out.push(a.address);
  return out.sort((a, b) => (/^100\./.test(b) ? 1 : 0) - (/^100\./.test(a) ? 1 : 0));        // a Tailscale address first: it reaches from anywhere
}

// ------------------------------------------------------------------ the standby clone
// A copy of this gate on another machine, kept up to date, started by that
// machine if this one stops answering.
//
// What goes over: app/ (plain JavaScript), config.json, secret.key and
// data/, minus data/fleet - the fleet key stays on this machine, so a clone
// cannot reach the rest of the machines.
export function standbyOn(fleet, id, { url, interval = 30, misses = 4, sshPort = 22, user } = {}) {
  const m = fleet.get(id);
  const clean = (v, n) => String(v ?? "").replace(/[^\w.:/@-]/g, "").slice(0, n);
  const watch = { url: clean(url, 300), host: clean(thisHost(), 120), name: clean(hostname(), 60) || "the main host",
                  sshPort: clamp(sshPort, 1, 65535), user: clean(user || userInfo().username, 40),
                  interval: clamp(interval, 10, 3600), misses: clamp(misses, 2, 60) };
  if (!/^https?:\/\//.test(watch.url)) fail("Give the address this gate answers on, so the clone can tell when it stops.");
  if (!watch.host || !watch.user) fail("This machine could not say what to call itself.");
  return fleet.start("standby", `Setting ${m.name} up as the standby`, id, async (job) => {
    job.step("Checking the machine can run it", 0.05);
    const pre = await fleet.ssh(m, `set -u
command -v node >/dev/null && node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>18||(a===18&&b>=17)?0:1)' && echo node=ok || echo node=no
command -v tar >/dev/null && echo tar=ok || echo tar=no
command -v ssh-keygen >/dev/null && echo keygen=ok || echo keygen=no
command -v systemctl >/dev/null && echo systemd=ok || echo systemd=no
echo home=$HOME`, { timeout: 30000 });
    if (!/node=ok/.test(pre.out)) fail(`${m.name} has no Node 18.17 or newer. Install Aegis \u00d7 Burrow on it first (that brings its own Node), then set the standby up.`);
    if (!/tar=ok/.test(pre.out)) fail(`${m.name} has no tar.`);
    const hasSystemd = /systemd=ok/.test(pre.out);
    job.log(hasSystemd ? "  systemd is there: the watcher runs as a user service" : "  no systemd: the watcher is started with nohup and cron");

    job.step("Packing this gate", 0.2);
    const tarFile = join(fleet.dir, `clone-${Date.now()}.tgz`);
    const t = await run("tar", ["-C", HOME, "--exclude=./data/fleet", "--exclude=./node", "--exclude=./bin",
                                "--exclude=./app/node_modules/.cache", "--exclude=./data/addons",
                                "-czf", tarFile, "."], { timeout: 10 * 60000 });
    if (t.code !== 0) fail(`could not pack this gate: ${t.err.split("\n").pop()}`);
    job.log(`  ${(statSync(tarFile).size / 1e6).toFixed(1)} MB (no fleet key, no private Node, no addons)`);

    try {
      job.step(`Copying it to ${m.name}`, 0.45);
      const remote = `/tmp/aegis-clone-${randomBytes(4).toString("hex")}.tgz`;
      await fleet.copyTo(m, tarFile, remote, 20 * 60000);

      job.step("Unpacking it and writing the watcher", 0.65);
      const r = await fleet.ssh(m, standbySetup({ remote, watch, hasSystemd }), { timeout: 5 * 60000 });
      if (r.code !== 0) fail(`setting the standby up failed: ${(r.err || r.out).split("\n").filter(Boolean).pop()}`);
      for (const l of r.out.split("\n").filter(Boolean)) job.log(l);
      const pub = /(^|\n)standby-key=(.+)/.exec(r.out);
      if (!pub) fail("the standby did not hand back a key to come back with");

      job.step("Letting it back in to restart this host", 0.85);
      const added = await allowStandbyKey(pub[2].trim(), m.id);
      job.log(added ? `  its key may now run the restart script here (${added})` : "  its key was already allowed here");

      fleet.patch(id, { standby: true, standbyState: { at: Date.now(), url: watch.url, interval: watch.interval,
                                                       misses: watch.misses, sshPort: watch.sshPort, user: watch.user, key: pub[2].trim() } });
      return { machine: id, url: watch.url };
    } finally { try { rmSync(tarFile, { force: true }); } catch { /* gone */ } }
  });
}

export function standbyRefresh(fleet, id) {
  const m = fleet.get(id);
  if (!m.standby) fail(`${m.name} is not the standby.`);
  return standbyOn(fleet, id, m.standbyState || {});
}

export function standbyOff(fleet, id) {
  const m = fleet.get(id);
  return fleet.start("standby-off", `Taking the standby off ${m.name}`, id, async (job) => {
    job.step("Stopping the watcher there", 0.2);
    const r = await fleet.ssh(m, `set -u
D="$HOME/.aegis-standby"
systemctl --user disable --now aegis-standby.service 2>/dev/null && echo "  stopped the user service" || true
rm -f "$HOME/.config/systemd/user/aegis-standby.service" 2>/dev/null || true
systemctl --user daemon-reload 2>/dev/null || true
(crontab -l 2>/dev/null | grep -v aegis-standby | crontab -) 2>/dev/null || true
[ -f "$D/watch.pid" ] && kill "$(cat "$D/watch.pid")" 2>/dev/null && echo "  stopped the watcher" || true
[ -f "$D/clone.pid" ] && kill "$(cat "$D/clone.pid")" 2>/dev/null && echo "  stopped the clone" || true
rm -rf "$D" && echo "  removed $D"`, { timeout: 2 * 60000 });
    for (const l of r.out.split("\n").filter(Boolean)) job.log(l);
    job.step("Taking its key off this machine", 0.8);
    const gone = await revokeStandbyKey(id);
    job.log(gone ? "  its key can no longer get in here" : "  it had no key here");
    fleet.patch(id, { standby: false, standbyState: null });
    return { machine: id };
  });
}

// The script that unpacks the clone, writes the watcher and starts it.
export function standbySetup({ remote, watch, hasSystemd }) {
  const unit = `[Unit]
Description=Aegis x Burrow standby watcher
After=network-online.target

[Service]
ExecStart=%h/.aegis-standby/watch.sh
Restart=always
RestartSec=20

[Install]
WantedBy=default.target
`;
  return `set -eu
D="$HOME/.aegis-standby"
# the clone is running (it took over): never unpack a new copy under it
if [ -f "$D/clone.pid" ] && kill -0 "$(cat "$D/clone.pid")" 2>/dev/null && [ -f "$D/id_ed25519.pub" ]; then
  rm -f ${sq(remote)}
  echo "  the clone here is running (it took over): left it as it is"
  echo "standby-key=$(cat "$D/id_ed25519.pub")"
  exit 0
fi
mkdir -p "$D/home"
rm -rf "$D/home.old" 2>/dev/null || true
[ -d "$D/home/app" ] && cp -a "$D/home" "$D/home.old" || true
tar -C "$D/home" -xzf ${sq(remote)}
rm -f ${sq(remote)}
rm -rf "$D/home.old"
chmod 700 "$D"
echo "  unpacked the clone into $D/home"

cat > "$D/env" <<'ENV'
MAIN_URL=${watch.url}
MAIN_HOST=${watch.host}
MAIN_NAME=${watch.name}
MAIN_SSH_PORT=${watch.sshPort}
MAIN_USER=${watch.user}
INTERVAL=${watch.interval}
MISSES=${watch.misses}
BACK=3
ENV

cat > "$D/revive.sh" <<'REVIVE'
${REVIVE}
REVIVE

cat > "$D/watch.sh" <<'WATCH'
${WATCH}
WATCH
chmod +x "$D/watch.sh" "$D/revive.sh"

[ -f "$D/id_ed25519" ] || ssh-keygen -t ed25519 -N '' -q -f "$D/id_ed25519" -C "aegis-standby@$(hostname)"
echo "standby-key=$(cat "$D/id_ed25519.pub")"

${hasSystemd ? `mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/aegis-standby.service" <<'UNIT'
${unit}UNIT
systemctl --user daemon-reload 2>/dev/null || true
systemctl --user enable --now aegis-standby.service 2>/dev/null && echo "  watcher running as a user service" || {
  nohup "$D/watch.sh" >> "$D/watch.log" 2>&1 & echo $! > "$D/watch.pid"; echo "  watcher running (nohup)"; }
loginctl enable-linger "$(id -un)" 2>/dev/null || true`
  : `pkill -f "$D/watch.sh" 2>/dev/null || true
nohup "$D/watch.sh" >> "$D/watch.log" 2>&1 & echo $! > "$D/watch.pid"
(crontab -l 2>/dev/null | grep -v aegis-standby; echo "@reboot $D/watch.sh >> $D/watch.log 2>&1") | crontab - 2>/dev/null || true
echo "  watcher running (nohup, and again at boot from cron)"`}
echo "  standby ready"
`;
}

// The watcher. Plain bash, no dependencies beyond curl and ssh.
export const WATCH = String.raw`#!/usr/bin/env bash
# Watches the machine this clone came from. If it stops answering, this
# starts the clone, writes down what happened, and keeps trying to start the
# other one again. When the other one is back, this clone steps aside.
set -u
D="$HOME/.aegis-standby"
. "$D/env"
CLONE="$D/home"
LOG="$D/watch.log"
say() { printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }

tcp() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }
# The main gate itself, not just anything on its address: once the clone runs
# it shares the domain, and its own answer must not count as the main being back.
web() {
  local b
  b=$(curl -skS --max-time 8 "$(printf %s "$MAIN_URL" | sed "s:/*$::")/__gate/health" 2>/dev/null) || return 1
  case "$b" in *'"standby":true'*) return 1 ;; *'"ok":true'*) return 0 ;; esac
  return 1
}

node_bin() { command -v node 2>/dev/null || echo "$CLONE/node/bin/node"; }

report() {  # report <reason> <reachable> <attempts>
  mkdir -p "$CLONE/data"
  cat > "$CLONE/data/takeover.json" <<JSON
{"at": $(date +%s)000, "main": "$MAIN_NAME", "url": "$MAIN_URL", "reason": "$1",
 "mainReachable": $2, "attempts": $3, "lastTry": $(date +%s)000, "handedBack": null}
JSON
}

start_clone() {
  [ -f "$D/clone.pid" ] && kill -0 "$(cat "$D/clone.pid")" 2>/dev/null && return 0
  ( cd "$CLONE" && AEGIS_HOME="$CLONE" AEGIS_STANDBY=1 AEGIS_NO_DEFAULT_ADDONS=1 nohup "$(node_bin)" "$CLONE/app/aegis/server.mjs" >> "$D/clone.log" 2>&1 & echo $! > "$D/clone.pid" )
  say "took over: started the clone (pid $(cat "$D/clone.pid"))"
}
stop_clone() {
  [ -f "$D/clone.pid" ] || return 0
  kill "$(cat "$D/clone.pid")" 2>/dev/null || true
  rm -f "$D/clone.pid"
  say "handed back: stopped the clone"
}

revive() {   # only when the other machine is up at all
  tcp "$MAIN_HOST" "$MAIN_SSH_PORT" || return 1
  ssh -i "$D/id_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="$D/known_hosts" -o ConnectTimeout=8 -p "$MAIN_SSH_PORT" \
      "$MAIN_USER@$MAIN_HOST" 'bash -s' < "$D/revive.sh" >> "$D/revive.log" 2>&1
}
revive_out() {   # the same, and say what the restart script said
  local n
  n=$(wc -l < "$D/revive.log" 2>/dev/null || echo 0)
  revive || true
  tail -n +"$((n+1))" "$D/revive.log" 2>/dev/null
}

miss=0; back=0; taken=0; tries=0; why=""
say "watching $MAIN_NAME at $MAIN_URL every $INTERVAL""s"
while true; do
  if web; then
    miss=0
    if [ "$taken" = 1 ]; then
      back=$((back+1))
      if [ "$back" -ge "$BACK" ]; then
        stop_clone; taken=0; back=0; tries=0
        sed -i 's/"handedBack": null/"handedBack": '"$(date +%s)"'000/' "$CLONE/data/takeover.json" 2>/dev/null || true
      fi
    fi
  else
    back=0
    miss=$((miss+1))
    if [ "$miss" -ge "$MISSES" ] && [ "$taken" = 0 ]; then
      why="$MAIN_NAME stopped answering at $MAIN_URL ($miss checks in a row, $INTERVAL""s apart)"
      say "$why"
      if tcp "$MAIN_HOST" "$MAIN_SSH_PORT"; then reach=true; else reach=false; fi
      # The machine is up: start Aegis there first. If its gate still answers
      # on that machine, it is slow or its way in is down, not gone - a second
      # copy with the same keys and domain would only fight it. Stay out.
      if [ "$reach" = true ]; then
        out=$(revive_out)
        case "$out" in
          *"already up"*) say "its gate still answers on $MAIN_NAME itself: not taking over"; miss=0; sleep "$INTERVAL"; continue ;;
          *revived*) say "started it again on $MAIN_NAME: not taking over"; miss=0; sleep "$INTERVAL"; continue ;;
        esac
      fi
      report "$why" "$reach" 0
      start_clone
      taken=1
    fi
    if [ "$taken" = 1 ]; then
      if tcp "$MAIN_HOST" "$MAIN_SSH_PORT"; then
        tries=$((tries+1))
        report "$why" true "$tries"
        say "the host is up: trying to start it again (attempt $tries)"
        revive && say "the restart script ran" || say "the restart script could not run"
      else
        report "$why" false "$tries"
      fi
    fi
  fi
  sleep "$INTERVAL"
done
`;

// The universal restart script: whatever way that machine runs Aegis, try it.
export const REVIVE = String.raw`#!/usr/bin/env bash
# Started by the standby clone, over SSH, on the machine that went quiet.
# It tries every way this machine might run Aegis x Burrow, in order, and
# stops at the first that brings it back.
set -u
cfg="$HOME/.config/aegis/aegis.json"
val() { sed -n 's/.*"'"$1"'": *"\([^"]*\)".*/\1/p' "$cfg" 2>/dev/null | head -1; }
unit=""; scope=""; cli=""; home=""; url=""
unit=$(val name); scope=$(val scope); cli=$(val cli); home=$(val home); url=$(val url)
up() { [ -n "$url" ] && curl -skS -o /dev/null --max-time 6 "$url" >/dev/null 2>&1; }

if up; then echo "already up"; exit 0; fi

if [ -n "$unit" ]; then
  if [ "$scope" = user ]; then systemctl --user start "$unit" 2>/dev/null && echo "systemctl --user start $unit"
  elif [ "$(id -u)" = 0 ]; then systemctl start "$unit" 2>/dev/null && echo "systemctl start $unit"
  else sudo -n systemctl start "$unit" 2>/dev/null && echo "sudo systemctl start $unit"; fi
  sleep 3; up && { echo revived; exit 0; }
fi

if [ -n "$cli" ] && [ -x "$cli" ]; then
  "$cli" start >/dev/null 2>&1 && echo "$cli start"
  sleep 3; up && { echo revived; exit 0; }
fi

if [ -n "$home" ] && [ -f "$home/app/aegis/server.mjs" ]; then
  node=$(command -v node || echo "$home/node/bin/node")
  ( cd "$home" && AEGIS_HOME="$home" nohup "$node" "$home/app/aegis/server.mjs" >> "$home/data/revive.log" 2>&1 & )
  echo "started it directly"
  sleep 4; up && { echo revived; exit 0; }
fi

echo "could not start it" >&2
exit 1
`;

// ------------------------------------------------------------------ this machine
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Math.round(Number(v) || lo)));
const thisHost = () => process.env.AEGIS_FLEET_HOST || hostname();

// Let the standby back in, only to run the restart script. One line in this
// user's authorized_keys, marked so it can be taken out again.
async function allowStandbyKey(pub, mid) {
  const line = `${pub.trim()} aegis-standby:${mid}`;
  const r = await run("bash", ["-s"], {
    input: `set -eu
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
f="$HOME/.ssh/authorized_keys"; touch "$f"; chmod 600 "$f"
grep -qF "aegis-standby:${mid}" "$f" && { echo existed; exit 0; }
printf '%s\\n' ${sq(line)} >> "$f"
echo added`, timeout: 15000 });
  if (r.code !== 0) fail(`could not let the standby back in: ${r.err || r.out}`);
  return r.out.includes("added") ? "added" : null;
}
async function revokeStandbyKey(mid) {
  const r = await run("bash", ["-s"], {
    input: `set -eu
f="$HOME/.ssh/authorized_keys"
[ -f "$f" ] || { echo none; exit 0; }
grep -qF "aegis-standby:${mid}" "$f" || { echo none; exit 0; }
grep -v "aegis-standby:${mid}" "$f" > "$f.aegis-tmp" && mv "$f.aegis-tmp" "$f" && chmod 600 "$f"
echo removed`, timeout: 15000 });
  return r.out.includes("removed");
}

// ------------------------------------------------------------------ after a takeover
// A clone that has taken over finds this on its first look. It is written by
// the watcher on the standby machine, and kept current while it keeps
// trying; the dashboard says so, and only claims it is trying to start the
// other host when that host is actually up.
export function takeover() {
  const t = readJson(join(DATA, "takeover.json"), null);
  if (!t || !t.at) return null;
  return { at: Number(t.at) || Date.now(), main: String(t.main || "the main host").slice(0, 80),
           url: String(t.url || "").slice(0, 300), reason: String(t.reason || "it stopped answering").slice(0, 300),
           mainReachable: t.mainReachable === true || t.mainReachable === "true",
           attempts: Number(t.attempts) || 0, lastTry: Number(t.lastTry) || null,
           handedBack: Number(t.handedBack) || null };
}

export function takeoverNotice(notify) {
  const t = takeover();
  if (!t || t.handedBack) return null;
  const seen = readJson(join(DATA, "takeover-seen.json"), {});
  const stamp = `${t.at}|${t.mainReachable}|${t.attempts > 0}`;
  if (seen.stamp === stamp) return t;
  writeJson(join(DATA, "takeover-seen.json"), { stamp, at: Date.now() });
  notify("fleet", {
    level: "critical",
    key: "takeover",
    title: `This is the standby: ${t.main} went down`,
    body: `${t.reason}. ${t.mainReachable
      ? `That host is answering on SSH, so this one is running the restart script on it${t.attempts ? ` (${t.attempts} ${t.attempts === 1 ? "attempt" : "attempts"} so far)` : ""}. Everything here is this gate's own copy: the same login, domain and tunnels.`
      : `That host is not answering at all, so there is nothing to start on it yet - this one keeps checking, and will run the restart script the moment it comes back.`}`,
    link: "/__gate/tunnels#/machines",
  });
  return t;
}
