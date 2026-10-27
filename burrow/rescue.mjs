// "Start it, whatever it takes": the rescue for an addon that is stopped or
// in error. It tries every way an addon on this machine could be started, in
// order, checking the addon's own status after each, and stops at the first
// that brings it back:
//
//   1. the addon's own "start" (or "restart") action
//   2. a start script it ships but doesn't declare (forge/restart.sh, start.sh…)
//   3. its systemd service: the user's, then the system's (sudo -n only)
//   4. its Docker containers
//   5. its install/update script again, as a repair (ADDON_ADOPT=1)
//
// A step that needs root (the addon's requires.root, or a start action with
// "root": true) is skipped and the report says so: a rescue never asks for a
// password and never runs anything as root by itself.
//
// Whatever happens, it writes one report: this machine, the addon, what each
// attempt printed, the status before and after, and - when it still won't
// run - the logs that say why (journal, docker logs, the addon's own *.log).
// The report is the job's result: the dashboard shows it, copies it and
// downloads it as a file. The last few are kept in data/addons/<id>/rescue/.
//
// Nothing here guesses beyond the addon's own name: a unit or container is
// only touched when its name (or label) is the addon's id.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { arch, cpus, freemem, hostname, release, totalmem, uptime, userInfo } from "node:os";
import { join } from "node:path";

const KEEP = 5;
const SETTLE_MS = Number(process.env.AEGIS_RESCUE_SETTLE_MS) || 4000;     // how long a started thing gets before its status is asked
const tidy = (s, n = 400) => String(s || "").replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").slice(-n * 200).split("\n").slice(-n).join("\n");

// What bash runs for the generic attempts and the diagnostics. Plain bash and
// coreutils; every tool is optional. $1 = what to do.
export const RESCUE_SH = String.raw`#!/usr/bin/env bash
set -u
id="$ADDON_ID"
what="$1"
if [ -z "\${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then export XDG_RUNTIME_DIR="/run/user/$(id -u)"; fi
if [ -z "\${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "\${XDG_RUNTIME_DIR:-/x}/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"; fi
user_units() { command -v systemctl >/dev/null && systemctl --user list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E "^(\${id}|\${id}-[a-z0-9-]+|forge-\${id})\.service$"; }
sys_units() { command -v systemctl >/dev/null && systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E "^(\${id}|\${id}-[a-z0-9-]+|forge-\${id})\.service$"; }
containers() { command -v docker >/dev/null && { docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Ex "(\${id}|\${id}-[a-z0-9_.-]+|forge-\${id})"; docker ps -a --filter "label=io.forge.addon=\${id}" --format '{{.Names}}' 2>/dev/null; } | sort -u; }
case "$what" in
  scripts)
    for s in forge/restart.sh forge/start.sh scripts/restart.sh scripts/start.sh bin/start.sh restart.sh start.sh; do
      [ -f "$ADDON_DIR/$s" ] && echo "$s"
    done ;;
  systemd-user)
    found=0
    for u in $(user_units); do
      found=1; echo "systemctl --user reset-failed $u; systemctl --user restart $u"
      systemctl --user reset-failed "$u" 2>/dev/null; systemctl --user enable "$u" >/dev/null 2>&1
      systemctl --user restart "$u" 2>&1 && echo "  restarted" || echo "  could not restart it"
    done
    [ "$found" = 1 ] || { echo "no user service named after $id"; exit 3; } ;;
  systemd-system)
    found=0
    for u in $(sys_units); do
      found=1
      if [ "$(id -u)" = 0 ]; then systemctl reset-failed "$u" 2>/dev/null; systemctl restart "$u" 2>&1 && echo "  systemctl restart $u"
      elif sudo -n true 2>/dev/null; then sudo -n systemctl reset-failed "$u" 2>/dev/null; sudo -n systemctl restart "$u" 2>&1 && echo "  sudo systemctl restart $u"
      else echo "  $u is a system service and this user cannot restart it without a password"; fi
    done
    [ "$found" = 1 ] || { echo "no system service named after $id"; exit 3; } ;;
  docker)
    command -v docker >/dev/null || { echo "no docker here"; exit 3; }
    found=0
    for c in $(containers); do found=1; docker start "$c" 2>&1 | sed 's/^/  started /'; done
    [ "$found" = 1 ] || { echo "no container named after $id"; exit 3; } ;;
  diagnose)
    echo "== services"
    for u in $(user_units); do echo "-- systemctl --user status $u"; systemctl --user status "$u" --no-pager -n 0 2>&1 | head -20
      echo "-- journalctl --user -u $u (last 120)"; journalctl --user -u "$u" -n 120 --no-pager 2>&1 | tail -120; done
    for u in $(sys_units); do echo "-- systemctl status $u"; systemctl status "$u" --no-pager -n 0 2>&1 | head -20
      echo "-- journalctl -u $u (last 120)"; journalctl -u "$u" -n 120 --no-pager 2>&1 | tail -120; done
    [ -n "$(user_units)$(sys_units)" ] || echo "(none named after $id)"
    echo "== containers"
    if [ -n "$(containers 2>/dev/null)" ]; then
      for c in $(containers); do echo "-- docker inspect $c"; docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} error={{.State.Error}}' "$c" 2>&1
        echo "-- docker logs $c (last 120)"; docker logs --tail 120 "$c" 2>&1 | tail -120; done
    else echo "(none named after $id)"; fi
    echo "== its own log files"
    n=0
    for f in $(find "$ADDON_DATA" "$ADDON_DIR" "$HOME/.local/share/$id" "$HOME/.config/$id" -maxdepth 3 -type f \( -name '*.log' -o -name '*.err' \) -size -50M 2>/dev/null | head -8); do
      n=1; echo "-- $f ($(wc -c < "$f") bytes, last 80 lines)"; tail -80 "$f" 2>&1; done
    [ "$n" = 1 ] || echo "(no *.log files in its folders)"
    echo "== this machine"
    echo "-- disk"; df -h "$ADDON_DIR" "$ADDON_DATA" "$HOME" 2>/dev/null | awk '!seen[$0]++'
    echo "-- memory"; free -m 2>/dev/null || true
    echo "-- out of memory kills (kernel, last 5)"; (journalctl -k --no-pager -n 400 2>/dev/null || dmesg 2>/dev/null) | grep -iE "out of memory|oom-kill|killed process" | tail -5 || true
    echo "-- listening ports (a port it needs may be taken; its own are marked <<)"
    (ss -ltnpH 2>/dev/null || netstat -ltnp 2>/dev/null) | awk '{print $4, $NF}' | sort -u | head -30 | sed "/\${id}/s/$/   <</" || true
    echo "-- processes named after it"; ps -eo pid,etime,rss,args 2>/dev/null | grep -i -- "$id" | grep -v -e grep -e rescue | head -10 || true ;;
esac
`.replace(/\\\$\{/g, "${");

function runBash(addons, rec, file, args, { job, timeout = 120 } = {}) {
  return new Promise((done) => {
    const root = addons.rootOf(rec), data = addons.dataDir(rec);
    const p = spawn("bash", [file, ...args], { cwd: root, env: addons.env(rec, root, data, {}), detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const out = [];
    let buf = "";
    const feed = (c) => {
      buf += c;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); out.push(l); if (out.length > 3000) out.splice(0, 1000); job?.log(l, "muted"); }
    };
    p.stdout.setEncoding("utf8"); p.stderr.setEncoding("utf8");
    p.stdout.on("data", feed); p.stderr.on("data", feed);
    const t = setTimeout(() => { try { process.kill(-p.pid, "SIGKILL"); } catch { /* gone */ } out.push(`(timed out after ${timeout}s)`); }, timeout * 1000);
    p.on("error", (e) => out.push(e.message));
    p.on("close", (code) => { clearTimeout(t); if (buf) out.push(buf); done({ code: code ?? 1, out: out.join("\n") }); });
  });
}

export async function rescue(addons, rec, job) {
  const m = rec.manifest, started = Date.now();
  const R = [];                                  // the report, section by section
  const sec = (title, body) => R.push(`\n## ${title}\n${String(body ?? "").trimEnd()}`);
  const dir = join(addons.addonDir(rec.id), "rescue");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const sh = join(dir, "rescue.sh");
  writeFileSync(sh, RESCUE_SH, { mode: 0o700 });

  const env = addons.hostEnv() || {};
  sec("About", [
    `addon:     ${m.name} (${m.id}) ${m.version}${rec.commit ? ` @ ${String(rec.commit).slice(0, 10)}` : ""}`,
    `source:    ${rec.source?.display || rec.source?.url || "?"}`,
    `installed: ${rec.installed_version || "?"}${rec.installed_at ? ` on ${new Date(rec.installed_at).toISOString()}` : ""}`,
    `host:      Aegis x Burrow ${addons.version}`,
    `machine:   ${hostname()} · ${process.platform} ${release()} ${arch()} · ${cpus().length} cores · ${(freemem() / 2 ** 30).toFixed(1)} of ${(totalmem() / 2 ** 30).toFixed(1)} GB free · up ${Math.round(uptime() / 3600)} h`,
    `user:      ${userInfo().username} (uid ${process.getuid?.() ?? "?"})`,
    `node:      ${process.version} at ${env.BURROW_NODE || process.execPath}`,
    `when:      ${new Date(started).toISOString()}`,
  ].join("\n"));

  const status = async (label) => {
    addons.statusCache.delete(rec.id);
    const st = await addons.status(rec, 0);
    job.log(`status ${label}: ${st.state}${st.detail ? ` - ${st.detail}` : ""}`, st.state === "running" ? "ok" : "");
    return st;
  };
  const before = await status("before");
  sec("Status before", `${before.state}${before.detail ? `\n${before.detail}` : ""}`);

  const tries = [];
  const needsRoot = (why) => ({ code: 3, out: `skipped: it needs administrator (root) access (${why}). Run it from the addon's card, where you can give it.` });
  const act = addons.startAction(rec);
  const actRoot = act ? addons.rootNeed(rec, "action", act.id) : "";
  if (act) tries.push({ name: `its own "${act.label}" action (${act.script})`, go: () => actRoot ? needsRoot(actRoot) : addons.run(rec, act.script, { job, timeout: 300 }).then((r) => ({ code: r.code, out: r.lines.join("\n") })) });
  const shipped = (await runBash(addons, rec, sh, ["scripts"], { timeout: 20 })).out.split("\n").map((x) => x.trim()).filter(Boolean)
    .filter((s) => !act || s !== act.script);
  if (shipped.length) tries.push({ name: `the start script it ships (${shipped[0]})`, go: () => addons.run(rec, shipped[0], { job, timeout: 300 }).then((r) => ({ code: r.code, out: r.lines.join("\n") })) });
  tries.push({ name: "its systemd user service", go: () => runBash(addons, rec, sh, ["systemd-user"], { job, timeout: 120 }) });
  tries.push({ name: "its systemd system service", go: () => runBash(addons, rec, sh, ["systemd-system"], { job, timeout: 120 }) });
  tries.push({ name: "its Docker containers", go: () => runBash(addons, rec, sh, ["docker"], { job, timeout: 180 }) });
  const fix = m.scripts.update || m.scripts.install;
  if (fix) tries.push({ name: `its ${m.scripts.update ? "update" : "install"} script again, as a repair (${fix})`, repair: true,
                        go: () => m.requires?.root ? needsRoot(m.requires.root) : addons.run(rec, fix, { job, extra: { ADDON_UPDATE: "1", ADDON_ADOPT: "1" }, timeout: 1800 }).then((r) => ({ code: r.code, out: r.lines.join("\n") })) });

  let after = before, worked = null;
  if (before.state === "running") {
    job.log(`${m.name} is already running. The report below is what it looks like now.`, "ok");
  } else {
    for (const [i, t] of tries.entries()) {
      if (job.cancelled) break;
      job.phase = `Trying ${t.name}`;
      job.progress = 0.08 + (0.75 * i) / tries.length;
      job.log(`--- ${i + 1}/${tries.length}: ${t.name}`, "head");
      let r;
      try { r = await t.go(); } catch (e) { r = { code: 1, out: e.message }; }
      const skipped = r.code === 3;
      if (!skipped) await new Promise((ok) => setTimeout(ok, t.repair ? SETTLE_MS * 2 : SETTLE_MS));
      after = skipped ? after : await status(`after ${t.name}`);
      sec(`Attempt ${i + 1}: ${t.name}`, `${skipped ? "nothing to try here" : `exit ${r.code} -> status ${after.state}${after.detail ? ` (${after.detail})` : ""}`}\n${tidy(r.out, 150)}`);
      if (after.state === "running") { worked = t.name; break; }
    }
  }
  if (after.state !== "running") {
    job.phase = "Collecting what went wrong";
    job.progress = 0.9;
    job.log("--- collecting logs", "head");
    sec("Diagnostics", tidy((await runBash(addons, rec, sh, ["diagnose"], { timeout: 60 })).out, 900));
  }
  const ok = after.state === "running";
  const verdict = before.state === "running" ? `${m.name} was already running.`
    : ok ? `${m.name} is running again: ${worked} brought it back.`
    : `${m.name} would not start. Every way was tried; the logs in this report say why.`;
  R.unshift(`# ${m.name}: start report\n\n${verdict}\nStatus now: ${after.state}${after.detail ? ` - ${after.detail}` : ""}`);
  const text = R.join("\n") + "\n";

  const file = `rescue-${new Date(started).toISOString().replace(/[:.]/g, "-").slice(0, 19)}.log`;
  writeFileSync(join(dir, file), text, { mode: 0o600 });
  const old = readdirSync(dir).filter((f) => /^rescue-.*\.log$/.test(f)).sort().slice(0, -KEEP);
  for (const f of old) rmSync(join(dir, f), { force: true });
  rmSync(sh, { force: true });
  job.log(verdict, ok ? "ok" : "err");
  if (ok && rec.down) addons.patch(rec.id, { down: null });
  return { id: rec.id, ok, state: after.state, worked, verdict, file, open_url: ok ? after.url || rec.open_url : null };
}

// One kept report (a name from reports()), or null.
export function report(addons, id, file) {
  if (!/^rescue-[0-9T-]+\.log$/.test(String(file || ""))) return null;
  const f = join(addons.addonDir(id), "rescue", file);
  return existsSync(f) ? readFileSync(f, "utf8") : null;
}

// The kept reports, newest first.
export function reports(addons, id) {
  const dir = join(addons.addonDir(id), "rescue");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => /^rescue-.*\.log$/.test(f)).sort().reverse()
    .map((f) => ({ file: f, at: statSync(join(dir, f)).mtimeMs, size: statSync(join(dir, f)).size }));
}
