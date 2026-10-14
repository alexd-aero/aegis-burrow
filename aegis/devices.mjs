// Your devices: every browser that signed in to Aegis, recognized for sure.
//
// A sign-in gives the browser a device key: a long-lived cookie (400 days,
// __Host-, bound to the host) sealed with the gate's secret, holding a random
// device id and the password's epoch. It can't be made up or changed (it's
// AES-GCM sealed), and the same id follows the browser onto each tunnel's
// host through the sign-in hop, so the gate knows which of your devices a
// request comes from, from any address, signed in right now or not.
//
// That is exact for every device that has signed in once. A device that never
// did (a phone on your Wi-Fi that only opens a public tunnel) carries nothing
// to recognize; it can only be guessed from its address, so that part stays a
// guess and is only ever used to protect (the address you signed in from is
// trusted), never to accuse.
//
// Forgetting a device makes its key worthless; changing the password forgets
// them all (the epoch moves).
//
// data/devices.json: {id: {first, last, ua, name, ips: {ip: last}, hosts: {host: last}}}

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { randomBytes } from "node:crypto";

const SEEN_EVERY_MS = 60e3;            // a device's address/host is noted at most once a minute
const KEEP_IPS = 20, KEEP_HOSTS = 30;
export const DEVICE_TTL_S = 400 * 86400;

// "Chrome on Windows", "Safari on iPhone"… from a User-Agent
export function deviceName(ua) {
  ua = String(ua || "");
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? (/Mobile/.test(ua) ? "Android phone" : "Android tablet")
    : /CrOS/.test(ua) ? "ChromeOS" : /Windows/.test(ua) ? "Windows" : /Mac OS X|Macintosh/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : null;
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\/|Opera/.test(ua) ? "Opera" : /SamsungBrowser/.test(ua) ? "Samsung Internet" : /Firefox\/|FxiOS/.test(ua) ? "Firefox"
    : /Chrome\/|CriOS/.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl\//.test(ua) ? "curl" : null;
  return br && os ? `${br} on ${os}` : br || os || "A browser";
}

export class Devices {
  constructor({ file, log }) {
    this.file = file;
    this.log = log || (() => {});
    this.map = new Map();
    try { for (const [id, d] of Object.entries(JSON.parse(readFileSync(file, "utf8")))) this.map.set(id, d); } catch { /* none yet */ }
    this.dirty = false;
    this.timer = setInterval(() => this.save(), 30e3);
    this.timer.unref?.();
  }
  save() {
    if (!this.dirty) return;
    this.dirty = false;
    try { writeFileSync(this.file + ".tmp", JSON.stringify(Object.fromEntries(this.map)), { mode: 0o600 }); renameSync(this.file + ".tmp", this.file); }
    catch (e) { this.log("devices: could not save", e.message); }
  }
  has(id) { return typeof id === "string" && this.map.has(id); }
  // a sign-in: the browser's device (the one it already had, or a new one)
  enroll(id, { ip, ua, host }) {
    if (!this.has(id)) {
      id = randomBytes(12).toString("base64url");
      this.map.set(id, { first: Date.now(), last: 0, ua: String(ua || "").slice(0, 300), name: null, ips: {}, hosts: {} });
      this.log("devices: a new device signed in:", deviceName(ua), ip);
    }
    this.seen(id, { ip, ua, host }, true);
    return id;
  }
  // a request from one of your devices
  seen(id, { ip, ua, host }, force = false) {
    const d = this.map.get(id);
    if (!d) return;
    const now = Date.now();
    if (!force && now - d.last < SEEN_EVERY_MS && d.ips[ip] && d.hosts[host]) return;
    d.last = now;
    if (ua) d.ua = String(ua).slice(0, 300);
    if (ip) d.ips[ip] = now;
    if (host) d.hosts[host] = now;
    const trim = (o, n) => { const k = Object.keys(o); if (k.length > n) for (const [x] of Object.entries(o).sort((a, b) => a[1] - b[1]).slice(0, k.length - n)) delete o[x]; };
    trim(d.ips, KEEP_IPS); trim(d.hosts, KEEP_HOSTS);
    this.dirty = true;
  }
  rename(id, name) {
    const d = this.map.get(id);
    if (!d) throw new Error("No such device.");
    d.name = String(name || "").trim().slice(0, 40) || null;
    this.dirty = true; this.save();
  }
  forget(id) { const ok = this.map.delete(id); if (ok) { this.dirty = true; this.save(); } return ok; }
  forgetAll() { this.map.clear(); this.dirty = true; this.save(); }
  // addresses your devices used lately: {ip: {last, devices: [id]}}
  addresses(sinceMs = 30 * 864e5) {
    const out = {}, cut = Date.now() - sinceMs;
    for (const [id, d] of this.map) for (const [ip, t] of Object.entries(d.ips)) if (t > cut) { const a = out[ip] ||= { last: 0, devices: [] }; a.last = Math.max(a.last, t); a.devices.push(id); }
    return out;
  }
  list(current) {
    return [...this.map].map(([id, d]) => ({ id, name: d.name || deviceName(d.ua), auto: deviceName(d.ua), named: !!d.name, first: d.first, last: d.last,
      ua: d.ua, this: id === current, ips: Object.entries(d.ips).sort((a, b) => b[1] - a[1]).map(([ip, t]) => ({ ip, last: t })),
      hosts: Object.entries(d.hosts).sort((a, b) => b[1] - a[1]).map(([host, t]) => ({ host, last: t })) }))
      .sort((a, b) => (b.this - a.this) || (b.last - a.last));
  }
  stop() { clearInterval(this.timer); this.save(); }
}
