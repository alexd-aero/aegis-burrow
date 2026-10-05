// Where Aegis keeps things, and the settings it runs with.
//
// AEGIS_HOME (default ~/.local/share/aegis):
//   config.json   written once by the installer: listen address, cookie, TLS...
//   secret.key    32 random bytes that seal session cookies (AES-256-GCM)
//   data/         everything Aegis writes while it runs:
//     state.json    the login, the linked domain, Termix (overrides config.json)
//     tunnels.json  metrics.json  favicons/  revoked.json
//     cf/           Cloudflare certificate, tunnel credentials, cloudflared config
//
// config.json is never written by the server, so it can sit on a read-only
// path (systemd ProtectHome=read-only) while data/ stays writable.

import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const APP = join(dirname(fileURLToPath(import.meta.url)), "..");
export const HOME = process.env.AEGIS_HOME || join(homedir(), ".local", "share", "aegis");
export const DATA = join(HOME, "data");
export const CONFIG_DIR = process.env.AEGIS_CONFIG_DIR
  || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "aegis");
export const INTEGRATIONS_DIR = join(CONFIG_DIR, "integrations");
export const VERSION = JSON.parse(readFileSync(join(APP, "package.json"), "utf8")).version;

export function readJson(path, fallback) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return fallback; }
}

export function writeJson(path, obj, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n", { mode });
  renameSync(tmp, path);
}

const DEFAULTS = {
  title: "Aegis",
  listen: { host: "127.0.0.1", port: 4310 },
  cookie: "__Host-aegis",
  tls: null,              // { key, cert } to serve HTTPS (TLS 1.3, post-quantum key exchange)
  domain: null,           // see cloudflare.mjs
  termix: null,           // { upstream, container? }
  extraHosts: [],         // more names that reach the dashboard (e.g. a Tailscale name)
};

export class Settings {
  constructor() {
    this.path = join(HOME, "config.json");
    this.statePath = join(DATA, "state.json");
    mkdirSync(DATA, { recursive: true });
    this.reload();
  }

  reload() {
    this.base = normalizeLegacy(readJson(this.path, {}));
    this.state = readJson(this.statePath, {});
  }

  get(key) {
    if (key in this.state) return this.state[key];
    if (key in this.base) return this.base[key];
    return DEFAULTS[key];
  }

  set(patch) {
    this.state = { ...this.state, ...patch };
    writeJson(this.statePath, this.state);
  }

  // The login lives in state.json (set by first-run setup or a password
  // change); an older install keeps it in config.json.
  auth() {
    const src = this.state.auth || (this.base.hash ? { username: this.base.username, salt: this.base.salt, hash: this.base.hash } : null);
    return src && src.hash ? src : null;
  }

  setupToken() {
    if (this.auth()) return null;
    return this.state.setupToken || this.base.setupToken || null;
  }
}

// The gate Aegis grew out of kept its domain flat in config.json
// (mainHost, tunnelId, cfCert, served by a cloudflared it did not run).
// Read that as an external domain so such an install runs this code as is.
function normalizeLegacy(cfg) {
  const out = { ...cfg };
  if (cfg.mainHost && cfg.tunnelId && !cfg.domain) {
    out.domain = { mainHost: cfg.mainHost.toLowerCase(), tunnelId: cfg.tunnelId, cert: cfg.cfCert, managed: false };
  }
  return out;
}
