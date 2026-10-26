// Burrow: cloning another Aegis × Burrow link.
//
// Every tunnel host answers GET /__gate/burrow with who may open it:
//   {burrow: 1, aegis: "2.30.0", access: "public" | "password" | "login", name}
// A public link, or one with a password of its own, can be cloned: this gate
// serves it on a name of its own (t.kind "clone"), fetching every request from
// the original. A link behind its owner's Aegis login can't be: only they can
// open it, and a copy would be a way around that.
//
// A password link hands out a clone key for its password: POST /__gate/clone
// with the password sealed the same way the unlock page seals it (X-Wing,
// AES-256-GCM twice), answered with {key}. The key goes with every request
// (x-burrow-clone) and works until the owner changes that password, which cuts
// every clone off at once. The password itself is never kept here.

import { webcrypto } from "node:crypto";
import { ml_kem768_x25519 as xwing } from "../aegis/vendor/pq.mjs";

const b64u = (b) => Buffer.from(b).toString("base64url");
const unb64u = (s) => new Uint8Array(Buffer.from(String(s), "base64url"));
const UA = "burrow/1 (clone)";
export const CLONE_HEADER = "x-burrow-clone";

// What people paste -> {host, url}: an https address, any path dropped (the whole host is cloned).
export function parseCloneUrl(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("Paste the link you want to clone.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch { throw new Error("That doesn't look like a link."); }
  if (u.protocol !== "https:") throw new Error("Only https links can be cloned.");
  if (u.username || u.password) throw new Error("Leave the name and password out of the link.");
  if (u.port && u.port !== "443") throw new Error("Aegis × Burrow links are on port 443.");
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(host)) throw new Error("That link has no proper host name.");
  if (/^(localhost|.*\.local|.*\.internal|.*\.lan)$/.test(host)) throw new Error("Only links out on the internet can be cloned.");
  return { host, url: `https://${host}/` };
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Ask the link who may open it. A gate whose shield checks new visitors first
// answers 403 "Checking your connection" once; it clears this machine in a moment.
export async function inspectClone(input, { fetchImpl = fetch, tries = 4, pause = 2500 } = {}) {
  const { host, url } = parseCloneUrl(input);
  let r, body = null;
  for (let i = 0; i < tries; i++) {
    try {
      r = await fetchImpl(url + "__gate/burrow", { redirect: "manual", signal: AbortSignal.timeout(10000), headers: { "user-agent": UA, accept: "application/json" } });
    } catch (e) { throw new Error(`Can't reach ${host}: ${e.cause?.code || e.message}.`); }
    if (r.status === 403 && i < tries - 1) { await wait(pause); continue; }
    try { body = await r.json(); } catch { body = null; }
    break;
  }
  if (r.status === 404 && body?.error === "paused") throw new Error(`${host} is paused by its owner right now.`);
  if (!r.ok || !body || body.burrow !== 1) throw new Error(`${host} isn't an Aegis × Burrow link, so it can't be cloned.`);
  const access = ["public", "password", "login"].includes(body.access) ? body.access : "login";
  return { host, url, access, name: String(body.name || "").slice(0, 60), aegis: String(body.aegis || "").slice(0, 20),
           clonable: access !== "login" };
}

// The password link's clone key, for its password (sealed on the way, as the unlock page does it).
export async function cloneKey(host, password, { fetchImpl = fetch } = {}) {
  const base = `https://${host}/__gate/`;
  const post = (path, body) => fetchImpl(base + path, {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(15000),
    headers: { "user-agent": UA, "content-type": "application/json", accept: "application/json" }, body: body ? JSON.stringify(body) : undefined });
  let r;
  try {
    r = await post("challenge");
    const ch = await r.json();
    r = await post("clone", await sealFor(ch, { password: String(password || "") }));
  } catch (e) { throw new Error(`Can't reach ${host}: ${e.cause?.code || e.message}.`); }
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) throw new Error(`That isn't the password of ${host}.`);
  if (r.status === 429) throw new Error(j.error || "Too many tries. Wait 15 minutes.");
  if (!r.ok || typeof j.key !== "string") throw new Error(j.error || `${host} didn't hand out a clone key (${r.status}).`);
  return j.key;
}

// The login page's sealing (client/login-entry.js), in Node.
export async function sealFor(ch, fields) {
  if (!ch || !ch.id || !ch.pk) throw new Error("no challenge");
  const { cipherText, sharedSecret } = xwing.encapsulate(unb64u(ch.pk));
  const key = async (label) => webcrypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-384", salt: new TextEncoder().encode(ch.id), info: new TextEncoder().encode(label) },
    await webcrypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]), { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv1 = webcrypto.getRandomValues(new Uint8Array(12)), iv2 = webcrypto.getRandomValues(new Uint8Array(12));
  const inner = new Uint8Array(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: iv1, additionalData: new TextEncoder().encode("inner|" + ch.id) },
    await key("aegis/v1/inner"), new TextEncoder().encode(JSON.stringify(fields))));
  const innerMsg = new Uint8Array(12 + inner.length);
  innerMsg.set(iv1); innerMsg.set(inner, 12);
  const outer = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: iv2, additionalData: new TextEncoder().encode("outer|" + ch.id) },
    await key("aegis/v1/outer"), innerMsg);
  return { id: ch.id, ct: b64u(cipherText), iv: b64u(iv2), c: b64u(outer) };
}
