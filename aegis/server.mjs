// Aegis × Burrow starts here, and this file stays small on purpose: it is the
// boot guard. The gate itself is gate.mjs, loaded below.
//
// After an update (or a rollback) the new version is "on trial" in
// data/boot.json until it has run for a minute (aegis/updater.mjs). If it
// doesn't load at all (a corrupted or broken download: a syntax error, a file
// missing) or it dies MAX_STARTS times before its minute is up, this puts the
// version before back (AEGIS_HOME/versions/<it>), keeps the failed one as
// versions/<v>-broken, and exits so the service manager starts the old code.
// The gate then holds the failed version back from auto-update and says so on
// the dashboard's bell. Only Node's own modules here: nothing else can break it.

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { spawn } from "node:child_process";

const APP = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = process.env.AEGIS_HOME || join(homedir(), ".local", "share", "aegis");
const BOOT = join(HOME, "data", "boot.json");
const VERSIONS = join(HOME, "versions");
const MAX_STARTS = 3;
const say = (...a) => console.error(new Date().toISOString(), "boot:", ...a);
const versionOf = (dir) => { try { return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version || null; } catch { return null; } };
const readBoot = () => { try { return JSON.parse(readFileSync(BOOT, "utf8")); } catch { return null; } };
const writeBoot = (b) => { try { mkdirSync(dirname(BOOT), { recursive: true }); writeFileSync(BOOT + ".tmp", JSON.stringify(b, null, 1)); renameSync(BOOT + ".tmp", BOOT); } catch { /* best effort */ } };

const me = versionOf(APP);
const boot = readBoot();
const onTrial = !!boot && boot.state === "trial" && boot.to === me && !process.env.AEGIS_NO_BOOT_GUARD;

function goBack(why) {
  const prev = join(VERSIONS, String(boot.from || ""));
  if (!boot.from || !existsSync(join(prev, "aegis", "server.mjs"))) {
    say(`${me} ${why}, and the version before (${boot.from || "?"}) isn't kept here: nothing to go back to. Try: aegis rollback`);
    writeBoot({ ...boot, state: "failed", why, at: Date.now() });
    return false;
  }
  const broken = join(VERSIONS, `${me}-broken`);
  try {
    rmSync(broken, { recursive: true, force: true });
    renameSync(APP, broken);
    renameSync(prev, APP);
  } catch (e) {
    say("going back failed:", e.message);
    if (!existsSync(APP) && existsSync(broken)) renameSync(broken, APP);
    return false;
  }
  writeBoot({ state: "rolled-back", from: me, to: boot.from, failed: me, why, at: Date.now(), starts: 0 });
  say(`${me} ${why}: went back to ${boot.from}; ${me} is kept as versions/${me}-broken`);
  return true;
}
// the old code starts: systemd's Restart=always does it; without systemd, a detached `aegis start`
function restartOld() {
  if (!process.env.INVOCATION_ID) {
    try { spawn("bash", ["-c", 'sleep 2; exec "$0" start', join(APP, "bin", "aegis")], { detached: true, stdio: "ignore", env: { ...process.env, AEGIS_HOME: HOME } }).unref(); } catch { /* by hand then */ }
  }
  setTimeout(() => process.exit(1), 300);
}

let wentBack = false;
if (onTrial) {
  const starts = (boot.starts || 0) + 1;
  if (starts > MAX_STARTS) wentBack = goBack(`stopped ${MAX_STARTS} times within its first minute`);
  else writeBoot({ ...boot, starts, lastStart: Date.now() });
}
if (wentBack) restartOld();
else {
  try {
    await import("./gate.mjs");
  } catch (e) {
    say("the gate didn't load:", (e && e.stack) || e);
    if (onTrial && goBack(`didn't load (${String((e && e.message) || e).split("\n")[0].slice(0, 200)})`)) restartOld();
    else process.exit(1);
  }
}
