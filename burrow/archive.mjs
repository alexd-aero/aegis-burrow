// Burrow, the engine: addon archives (.zip, .tar.gz, .tgz), with no
// dependencies. Downloaded with a size cap, unpacked into a fresh folder, and
// refused outright when anything could escape it (absolute paths, "..",
// drive letters) or is too big. Links are never unpacked. A single top-level
// folder (GitHub's and GitLab's archive links have one) is dropped, the same as
// Selkies Forge does (src/forge/addons.py: fetch_archive).

import { createHash } from "node:crypto";
import { inflateRawSync, gunzipSync } from "node:zlib";
import { mkdirSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const LIMITS = { download: 200 << 20, unpacked: 500 << 20, files: 20000 };

export class ArchiveError extends Error {}
const fail = (m) => { throw new ArchiveError(m); };
const safe = (n) => !!n && !n.startsWith("/") && !n.split("/").includes("..") && !/^[A-Za-z]:/.test(n) && !n.includes("\0");

export async function download(url, ua) {
  let r;
  try { r = await fetch(url, { headers: { "User-Agent": ua }, redirect: "follow", signal: AbortSignal.timeout(120000) }); }
  catch (e) { fail(`Could not download ${url}: ${e.cause?.message || e.message}`); }
  if (!r.ok) fail(`Could not download ${url}: HTTP ${r.status}`);
  const chunks = [];
  let got = 0;
  for await (const c of r.body) {
    got += c.length;
    if (got > LIMITS.download) fail(`The archive is larger than ${LIMITS.download >> 20} MB.`);
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

// [{name, dir, data()}] from a zip (stored or deflated entries; no zip64)
function zipEntries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) fail("That is not a valid .zip archive.");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  if (count > LIMITS.files) fail(`The archive holds more than ${LIMITS.files} files.`);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) fail("The .zip archive is damaged.");
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), size = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const attr = buf.readUInt32LE(p + 38), local = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nlen).replace(/\\/g, "/");
    p += 46 + nlen + xlen + clen;
    if (csize === 0xffffffff || size === 0xffffffff) fail("zip64 archives are not supported; use a .tar.gz.");
    if (!safe(name)) fail(`The archive has an unsafe path: ${name.slice(0, 120)}`);
    if (((attr >>> 16) & 0o170000) === 0o120000) continue;          // a link: skipped
    const dir = name.endsWith("/");
    out.push({ name: name.replace(/\/$/, ""), dir, size, data: () => {
      const l = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
      const raw = buf.subarray(l, l + csize);
      if (method === 0) return raw;
      if (method === 8) return inflateRawSync(raw, { maxOutputLength: Math.max(size, 1) });
      fail(`Unsupported compression in ${name}`);
    } });
  }
  return out;
}

// [{name, dir, data()}] from a (gzipped) ustar/pax/GNU tar
function tarEntries(buf) {
  if (buf[0] === 0x1f && buf[1] === 0x8b) {
    try { buf = gunzipSync(buf, { maxOutputLength: LIMITS.unpacked + (1 << 20) }); } catch { fail("That is not a valid .tar.gz archive (or it unpacks to too much)."); }
  }
  const out = [];
  let p = 0, longName = null, pax = {};
  const str = (o, n) => buf.toString("utf8", o, o + n).replace(/\0.*$/s, "");
  while (p + 512 <= buf.length) {
    if (buf.subarray(p, p + 512).every((b) => b === 0)) break;
    const size = parseInt(str(p + 124, 12).trim() || "0", 8);
    const type = String.fromCharCode(buf[p + 156] || 48);
    const prefix = str(p + 345, 155);
    let name = longName || pax.path || (prefix ? `${prefix}/${str(p, 100)}` : str(p, 100));
    const dataAt = p + 512;
    p = dataAt + Math.ceil(size / 512) * 512;
    if (type === "L") { longName = buf.toString("utf8", dataAt, dataAt + size).replace(/\0.*$/s, ""); continue; }
    if (type === "x") {
      pax = {};
      for (const rec of buf.toString("utf8", dataAt, dataAt + size).split("\n")) { const m = /^\d+ ([^=]+)=(.*)$/.exec(rec); if (m) pax[m[1]] = m[2]; }
      continue;
    }
    if (type === "g") continue;
    longName = null; pax = {};
    name = name.replace(/^\.\//, "").replace(/\/$/, "");
    if (!name) continue;
    if (!safe(name)) fail(`The archive has an unsafe path: ${name.slice(0, 120)}`);
    if (type === "5") out.push({ name, dir: true, size: 0, data: () => Buffer.alloc(0) });
    else if (type === "0" || type === "\0" || type === "7") out.push({ name, dir: false, size, data: () => buf.subarray(dataAt, dataAt + size) });
    // links, devices and fifos are skipped
    if (out.length > LIMITS.files) fail(`The archive holds more than ${LIMITS.files} files.`);
  }
  if (!out.length) fail("That is not a valid .tar.gz archive.");
  return out;
}

// Unpack buf into dest (which must not exist). Returns "sha256:<hex>" of the download.
export function unpack(buf, dest) {
  const digest = "sha256:" + createHash("sha256").update(buf).digest("hex");
  const isZip = buf.readUInt32LE(0) === 0x04034b50 || buf.readUInt32LE(0) === 0x06054b50;
  const entries = isZip ? zipEntries(buf) : tarEntries(buf);
  const total = entries.reduce((n, e) => n + e.size, 0);
  if (total > LIMITS.unpacked) fail(`The archive unpacks to more than ${LIMITS.unpacked >> 20} MB.`);
  const tmp = dest + ".unpacked";
  mkdirSync(tmp, { recursive: true });
  for (const e of entries) {
    const p = join(tmp, e.name);
    if (e.dir) { mkdirSync(p, { recursive: true }); continue; }
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, e.data(), { mode: 0o644 });
  }
  let root = tmp;
  const names = readdirSync(tmp);
  if (names.length === 1 && statSync(join(tmp, names[0])).isDirectory() && !names.includes("forge-addon.json")) root = join(tmp, names[0]);
  mkdirSync(dest, { recursive: true });
  for (const n of readdirSync(root)) renameSync(join(root, n), join(dest, n));
  rmSync(tmp, { recursive: true, force: true });
  return digest;
}
