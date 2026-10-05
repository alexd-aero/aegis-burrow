// The bridge: Aegis × Burrow <-> Selkies Forge, both ways.
//
//   Forge -> us   The Forge adds this repository as an addon (its Addons page),
//                 and keeps ~/.config/aegis/integrations/selkies-forge.json
//                 current, with an "addon" block that says how it runs us.
//   us -> Forge   Burrow → Selkies Forge → Connect: we check our own
//                 forge-addon.json with the same rules the Forge uses, then ask
//                 the Forge's API to add and link us.
//   both          Whichever side starts it, the other follows: once the Forge
//                 has us as an addon, Burrow adds the Forge as one of its own
//                 addons (from the Forge's checkout, which carries a manifest
//                 made for Burrow), so each shows up in the other's Addons.
//
// health() says whether the link is up and private, check by check:
//   {state: ok|warn|fail|off, checks: [{id, label, state, detail, fix?}], forgeSide}

import { lstatSync, statSync, existsSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { APP, DATA, INTEGRATIONS_DIR } from "./config.mjs";
import { listIntegrations } from "./integrations.mjs";
import { loadManifest, versionTuple } from "../burrow/addons.mjs";

const tilde = (p) => String(p || "").replace(homedir(), "~");
const PRIVATE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|localhost$|\[?::1\]?$|[a-z0-9-]+\.local$|[a-z0-9-]+$)/i;

export function forgeIntegration() {
  return listIntegrations().find((i) => i.kind === "selkies-forge") || null;
}

async function forgeCall(forge, path, body, ms = 15000) {
  const t0 = Date.now();
  const r = await fetch(new URL(path, forge.api), {
    method: body ? "POST" : "GET", signal: AbortSignal.timeout(ms),
    headers: { Accept: "application/json", "X-Burrow-Client": "aegis-burrow", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `Selkies Forge answered HTTP ${r.status}`);
  return { ...j, _ms: Date.now() - t0 };
}

// The file (a socket may be a link to a short path; the link and its target both count).
function fileMode(p) {
  try {
    const l = lstatSync(p), s = statSync(p);
    return { mode: s.mode & 0o777, uid: l.isSymbolicLink() && l.uid !== s.uid ? -1 : s.uid, sock: s.isSocket(), file: s.isFile(), link: l.isSymbolicLink() };
  } catch { return null; }
}

export async function health({ burrow, addons }) {
  const checks = [];
  const add = (id, label, state, detail, fix) => checks.push({ id, label, state, detail, ...(fix ? { fix } : {}) });
  const forge = forgeIntegration();
  const man = (() => { try { return loadManifest(APP); } catch (e) { return { error: e.message }; } })();

  add("manifest", "Our forge-addon.json is valid", man.error ? "fail" : "ok",
      man.error || `${man.id} ${man.version} · spec ${man.spec} · ${man.platforms.join(" + ")}`);

  // the socket the Forge publishes through: ours, and private
  const sock = join(DATA, "control.sock"), sm = fileMode(sock);
  const dm = fileMode(sm?.link ? dirname(realpathSync(sock)) : DATA);
  if (!sm) add("socket", "Control socket is private", "fail", `${tilde(sock)} is missing`);
  else {
    const bad = [];
    if (!sm.sock) bad.push("not a socket");
    if (sm.uid !== process.getuid()) bad.push("owned by another user");
    if (sm.mode & 0o077) bad.push(`mode ${sm.mode.toString(8)}: others can connect`);
    if (dm && dm.mode & 0o077) bad.push(`its folder is mode ${dm.mode.toString(8)}`);
    add("socket", "Control socket is private", bad.length ? "fail" : "ok",
        bad.join("; ") || `${tilde(sock)} · mode ${sm.mode.toString(8)} · folder ${dm ? dm.mode.toString(8) : "?"} · yours`);
  }

  if (!forge) {
    add("forge", "Selkies Forge on this machine", "off", "no Forge has registered here: install it, or add it under Addons");
    return finish(checks, null);
  }
  add("forge", "Selkies Forge on this machine", "ok", `${forge.name} ${forge.version} · ${tilde(forge.url)}`);

  // its drop-in: current, and only writable by us
  const drop = join(INTEGRATIONS_DIR, `${forge.id}.json`), fm = fileMode(drop);
  const age = forge.updated ? Date.now() / 1000 - forge.updated : Infinity;
  const loose = fm && (fm.uid !== process.getuid() || fm.mode & 0o022);
  add("dropin", "It registered itself here", loose ? "fail" : age < 3 * 3600 ? "ok" : "warn",
      loose ? `${tilde(drop)} can be rewritten by ${fm.uid !== process.getuid() ? "another user" : `group or others (mode ${fm.mode.toString(8)})`}`
            : `${tilde(drop)} · refreshed ${ago(age)} ago`);

  // does it answer?
  let forgeSide = null;
  try {
    forgeSide = await forgeCall(forge, "bridge", null, 20000).catch(async (e) => {
      if (/HTTP 404/.test(e.message)) { const r = await forgeCall(forge, "burrow"); return { state: null, checks: [], _ms: r._ms, old: true }; }
      throw e;
    });
    add("answer", "The Forge answers", "ok", `${forgeSide._ms} ms · ${tilde(forge.api)}${forgeSide.old ? " · update it for its own bridge check" : ""}`);
  } catch (e) {
    add("answer", "The Forge answers", "fail", `${tilde(forge.api)}: ${e.message}`);
  }

  // private addresses only
  let host = "";
  try { host = new URL(forge.api).hostname; } catch { /* */ }
  add("private", "The Forge's API stays private", PRIVATE.test(host) ? "ok" : "warn",
      PRIVATE.test(host) ? `${host} is this machine or a private network` : `${host} looks public: anyone who reaches it can drive the Forge`);

  // each side has the other as an addon
  const ad = forge.addon;
  add("forge-has-us", "Aegis × Burrow is a Forge addon", ad ? "ok" : "warn",
      ad ? `${ad.id} ${ad.version}${ad.commit ? ` · ${ad.commit.slice(0, 7)}` : ""} · ${ad.adopted ? "linked" : "installed by the Forge"}${ad.state ? ` · ${ad.state}` : ""}`
         : "not yet: press Connect, or add it on the Forge's Addons page", ad ? null : "connect");
  let mine = null;
  try { mine = addons.get("selkies-forge"); } catch { /* none */ }
  add("we-have-forge", "Selkies Forge is a Burrow addon", mine?.installed ? "ok" : "warn",
      mine?.installed ? `selkies-forge ${mine.installed_version || ""} · ${mine.adopted ? "linked" : "installed"} from ${tilde(mine.source?.display)}`
                      : "not yet: Connect adds it, from the Forge's own checkout", mine?.installed ? null : "connect");

  // what came through the socket
  const fc = burrow.controlView().clients.find((c) => c.id === "selkies-forge");
  add("calls", "The Forge uses the bridge", "ok", fc ? `${fc.calls} call${fc.calls === 1 ? "" : "s"} · last ${ago((Date.now() - fc.last) / 1000)} ago` : "no calls since Aegis started (it calls when you publish a desktop)");

  // its dashboard behind a login?
  const pub = forge.port && burrow.tunnels.list().find((t) => t.targetPort === forge.port && t.access === "public" && t.enabled);
  add("exposed", "The Forge's dashboard needs a login", pub ? "warn" : "ok",
      pub ? `${pub.url || `tunnel ${pub.port}`} publishes it to anyone. Fine if you meant it; switch that tunnel to Login otherwise.`
          : "no public tunnel to it");

  // versions
  const want = man.requires?.forge?.replace(/^>=\s*/, "");
  if (want) {
    const okv = cmp(versionTuple(forge.version), versionTuple(want)) >= 0;
    add("versions", "Versions fit", okv ? "ok" : "fail", `Forge ${forge.version}, we need ${want} or newer`);
  }
  return finish(checks, forgeSide && !forgeSide.old ? { state: forgeSide.state, checks: forgeSide.checks || [] } : null);
}

const cmp = (a, b) => { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };
function ago(s) { s = Math.max(0, Math.round(s)); return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : s < 86400 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`; }
function finish(checks, forgeSide) {
  let state = "ok";
  if (checks.some((c) => c.id === "forge" && c.state === "off")) state = "off";
  if (checks.some((c) => c.state === "fail")) state = "fail";
  else if (state === "ok" && checks.some((c) => c.state === "warn")) state = "warn";
  return { state, checks, forgeSide, checked: Date.now() };
}

// Us -> Forge: check our manifest, then have the Forge add and link us.
export async function submitToForge({ log }) {
  const forge = forgeIntegration();
  if (!forge) throw new Error("Selkies Forge isn't on this machine (no drop-in from it yet).");
  const m = loadManifest(APP);                         // throws with exactly what is wrong
  if (!m.platforms.includes("selkies-forge")) throw new Error("Our manifest isn't made for Selkies Forge.");
  const tries = [m.homepage, APP].filter(Boolean);
  let added = null, lastErr = null;
  for (const source of tries) {
    try { added = (await forgeCall(forge, "addons/add", { source }, 240000)).addon; break; } catch (e) { lastErr = e; }
  }
  if (!added) throw new Error(`The Forge could not add us: ${lastErr?.message}`);
  if (added.installed) return { already: true, id: added.id, page: forge.url + `#addons/${added.id}` };
  const job = await forgeCall(forge, `addons/${added.id}/install`, { settings: {} }, 30000);
  log("bridge: submitted ourselves to Selkies Forge as", added.id, added.detected?.found ? "(linking)" : "(installing)");
  return { id: added.id, job: job.job || null, page: forge.url + `#addons/${added.id}` };
}

// Forge -> us: add the Forge as one of our addons, from its own checkout.
export async function adoptForge({ addons, log }) {
  const forge = forgeIntegration();
  if (!forge) return null;
  try { if (addons.get("selkies-forge").installed) return null; } catch { /* not yet */ }
  const repo = forge.home ? join(forge.home, "repo") : null;
  if (!repo || !existsSync(join(repo, "forge-addon.json"))) return null;      // a Forge too old to carry its manifest
  try { if (!statSync(repo).isDirectory()) return null; } catch { return null; }
  const a = await addons.add(repo);
  log("bridge: added Selkies Forge as a Burrow addon from", tilde(repo));
  return addons.install(a.id, {});
}
