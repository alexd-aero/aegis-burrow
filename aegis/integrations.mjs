// Integrations: other apps on this machine that plug into the dashboard.
//
// An app installs itself by dropping one JSON file into
//   ~/.config/aegis/integrations/<id>.json
// and keeping it current. Aegis reads the folder on every request (it is
// tiny), so there is nothing to register and nothing to restart.
//
//   {
//     "spec": 1,
//     "id": "selkies-forge",            lowercase letters, digits, dashes
//     "kind": "selkies-forge",          what Aegis knows how to talk to
//     "name": "Selkies Forge",
//     "version": "1.10.0",
//     "url": "http://127.0.0.1:8787/",  its dashboard, as this machine reaches it
//     "api": "http://127.0.0.1:8787/api/",
//     "port": 8787,                     the port its dashboard listens on
//     "public_url": null,               an address it published itself, if any
//     "logo": "<svg …>",                inline SVG, at most 64 KB
//     "addon": {…},                     optional: how that app runs Aegis × Burrow
//                                       as an addon (Selkies Forge writes it)
//     "updated": 1760000000
//   }
//
// Any kind gets a card on the Tunnels page that links to its dashboard.
// kind "selkies-forge" also gets a full panel: every desktop with its links,
// start/stop/restart, and one-click publishing through a Aegis tunnel.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { APP, INTEGRATIONS_DIR, readJson } from "./config.mjs";

const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const NAME_RE = /^[A-Za-z0-9._-]{1,128}$/;

function httpUrl(u) {
  try { const x = new URL(String(u)); return x.protocol === "http:" || x.protocol === "https:" ? x.href : null; }
  catch { return null; }
}

// What an app says about the addon it runs us as (all strings, all short).
function cleanAddon(a) {
  if (!a || typeof a !== "object") return null;
  const s = (v, n = 120) => (v == null ? null : String(v).slice(0, n));
  const up = a.update && typeof a.update === "object" ? a.update : null;
  return {
    id: s(a.id, 40), name: s(a.name, 60), version: s(a.version, 30), commit: s(a.commit, 40),
    source: httpUrl(a.source), state: s(a.state, 20), adopted: !!a.adopted,
    installedAt: Number(a.installed_at) || null, checkedAt: Number(a.checked_at) || null,
    update: up ? { available: !!up.available, commit: s(up.commit, 40), version: s(up.version, 30),
                   subject: s(up.subject, 160), behind: Number(up.behind) || 0 } : null,
    page: httpUrl(a.page),
  };
}

// A Selkies Forge drop-in left behind is not a Forge: it counts while the
// Forge keeps it fresh (every 20 s while it runs) or its install is still on
// disk (it may just be stopped). Otherwise the Forge was removed, and Burrow
// never offers to link with, or install, something that isn't here.
function forgeStillHere(d) {
  const age = Date.now() / 1000 - (Number(d.updated) || 0);
  if (age < 15 * 60) return true;
  const home = typeof d.home === "string" && d.home.startsWith("/") ? d.home : null;
  return !!home && (existsSync(join(home, "app", "engine.py")) || existsSync(join(home, "engine.py")));
}

export function listIntegrations(dir = INTEGRATIONS_DIR) {
  let names = [];
  try { names = readdirSync(dir).filter((n) => n.endsWith(".json")); } catch { return []; }
  const out = [];
  for (const n of names.sort()) {
    try {
      const p = join(dir, n);
      if (statSync(p).size > 128 * 1024) continue;
      const d = JSON.parse(readFileSync(p, "utf8"));
      if (!ID_RE.test(d.id || "") || n !== `${d.id}.json`) continue;
      if (String(d.kind || d.id) === "selkies-forge" && !forgeStillHere(d)) continue;
      out.push({
        id: d.id, kind: String(d.kind || d.id).slice(0, 40), name: String(d.name || d.id).slice(0, 60),
        version: String(d.version || "").slice(0, 30), url: httpUrl(d.url), api: httpUrl(d.api),
        publicUrl: httpUrl(d.public_url), port: Number(d.port) || null,
        logo: typeof d.logo === "string" && d.logo.length <= 65536 && /^\s*<svg[\s>]/i.test(d.logo) ? d.logo : null,
        updated: Number(d.updated) || null,
        addon: cleanAddon(d.addon),
        home: typeof d.home === "string" && d.home.startsWith("/") ? d.home : null,
      });
    } catch { /* skip a half-written or broken file */ }
  }
  return out;
}

export function getIntegration(id) {
  return listIntegrations().find((i) => i.id === id) || null;
}

// A tunnel that already publishes this integration's dashboard, if any.
function dashboardTunnel(integ, tunnels) {
  if (!integ.port) return null;
  const local = new Set(["127.0.0.1", "localhost", "::1"]);
  try { local.add(new URL(integ.url).hostname); } catch { /* ignore */ }
  return tunnels.list().find((t) => t.targetPort === integ.port && local.has(t.targetHost) && t.url) || null;
}

export function publicView(integ, tunnels) {
  const t = dashboardTunnel(integ, tunnels);
  return {
    id: integ.id, kind: integ.kind, name: integ.name, version: integ.version,
    logo: integ.logo ? `/__gate/api/integrations/${integ.id}/logo?v=${integ.updated || 0}` : null,
    // where "Open dashboard" goes: our own tunnel first, then its own public
    // address, then the address this machine uses
    dashboard: t?.url || integ.publicUrl || integ.url,
    local: integ.url, viaTunnel: t ? t.port : null, full: integ.kind === "selkies-forge",
  };
}

// ---------------------------------------------------------------- Selkies Forge
async function forgeCall(integ, path, body) {
  if (!integ.api) throw new Error("This integration has no API address.");
  const r = await fetch(new URL(path, integ.api), {
    method: body ? "POST" : "GET",
    headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(body ? 240000 : 10000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `Selkies Forge answered HTTP ${r.status}`);
  return j;
}

export async function forgeDesktops(integ, tunnels) {
  let inst;
  try { inst = (await forgeCall(integ, "instances")).instances || []; }
  catch (e) { return { reachable: false, error: e.message, desktops: [] }; }
  const byPort = new Map(tunnels.list().map((t) => [t.targetPort, t]));
  const desktops = inst.map((i) => {
    const kasm = i.profile === "kasm";
    const port = (i.ports || {})[kasm ? "6901" : "3000"] || null;
    const tun = port ? byPort.get(port) : null;
    const ft = i.tunnel && i.tunnel.alive !== false ? i.tunnel.url : null;
    return {
      name: i.name, title: i.title || i.name, running: !!i.running, status: i.status || (i.running ? "running" : "exited"),
      health: i.health || null, de: i.de_label || "", family: i.family || "", profile: i.profile || "selkies",
      port, scheme: kasm ? "https" : "http", localUrl: i.local_url || null, startedAt: i.started_at || null,
      forgeTunnel: ft,
      tunnel: tun ? { port: tun.port, url: tun.url, enabled: tun.enabled, access: tun.access, up: tun.health?.up ?? null } : null,
    };
  }).sort((a, b) => (b.running - a.running) || a.title.localeCompare(b.title));
  return { reachable: true, desktops, running: desktops.filter((d) => d.running).length };
}

export async function forgeAction(integ, name, action) {
  if (!NAME_RE.test(name || "")) throw new Error("Bad desktop name.");
  if (!["start", "stop", "restart"].includes(action)) throw new Error("Unknown action.");
  return forgeCall(integ, `instance/${encodeURIComponent(name)}/${action}`, {});
}

// ---------------------------------------------------------------- us, as an addon
//
// Burrow → Addon tab: is Aegis × Burrow running as a Selkies Forge addon,
// which version and commit, is there an update, and what has the Forge done
// through Burrow's control socket. The Forge says it all in its drop-in file
// (the "addon" block); the manifest is our own forge-addon.json.
export function addonView({ tunnels, control, burrow }) {
  const m = readJson(join(APP, "forge-addon.json"), {}) || {};
  const forge = listIntegrations().find((i) => i.kind === "selkies-forge") || null;
  const ageS = forge?.updated ? Math.max(0, Math.round(Date.now() / 1000 - forge.updated)) : null;
  return {
    manifest: {
      id: m.id, name: m.name, version: m.version, homepage: m.homepage, spec: m.spec,
      scripts: Object.keys(m.scripts || {}),
      actions: (m.actions || []).map((a) => ({ id: a.id, label: a.label })),
      settings: (m.settings || []).map((x) => ({ key: x.key, label: x.label, type: x.type })),
      integration: m.integration?.dir || null,
    },
    forge: forge ? { ...publicView(forge, tunnels), heartbeat: forge.updated, fresh: ageS != null && ageS < 3 * 3600,
                     dropin: join(INTEGRATIONS_DIR, forge.id + ".json").replace(homedir(), "~") } : null,
    addon: forge?.addon || null,
    control, burrow,
  };
}
