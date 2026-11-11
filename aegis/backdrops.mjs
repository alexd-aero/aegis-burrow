// Your own backgrounds, for themes that draw one (Weft spec §12.6). They live
// on this machine only, in data/backdrops, never in Aegis or in a theme: what
// you put behind your dashboard is yours.
//
// Three kinds:
//   image  three JPEGs the browser makes before it uploads (Aegis has no image
//          library): l (up to 3840 px wide, big screens), s (1280 px, phones)
//          and t (40 px, shown blurred while the real one loads)
//   gif    the file as it is, plus a still t.jpg when the browser could make one
//   video  .mp4 or .webm as it is (played muted, looped), plus a still t.jpg
//
// From a link (link()): a wallpaperflare page (its full-size picture is found
// on its download page), a direct link to a picture, GIF or video, or any page
// that names a preview picture (og:image). SVG never: it can carry scripts.
// The download only ever connects to public addresses, checked again on every
// redirect, so a link can't make this machine reach into your network.

import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, renameSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import http from "node:http";
import https from "node:https";

export const MAX = { l: 12e6, s: 3e6, t: 64e3, gif: 30e6, video: 90e6, page: 3e6, image: 40e6 };
export const LIMIT = 64;                                // pictures kept
const ID = /^[a-z0-9][a-z0-9-]{0,39}$/;

export class BackdropError extends Error {}
const fail = (m) => { throw new BackdropError(m); };

// What the bytes are, whatever the link or the file name said.
export function sniff(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { kind: "image", type: "image/jpeg", ext: "jpg" };
  if (buf.readUInt32BE(0) === 0x89504e47) return { kind: "image", type: "image/png", ext: "png" };
  if (buf.toString("latin1", 0, 4) === "RIFF" && buf.toString("latin1", 8, 12) === "WEBP") return { kind: "image", type: "image/webp", ext: "webp" };
  if (buf.toString("latin1", 4, 12) === "ftypavif" || buf.toString("latin1", 4, 12) === "ftypavis") return { kind: "image", type: "image/avif", ext: "avif" };
  if (buf[0] === 0x42 && buf[1] === 0x4d) return { kind: "image", type: "image/bmp", ext: "bmp" };
  if (buf.toString("latin1", 0, 6) === "GIF87a" || buf.toString("latin1", 0, 6) === "GIF89a") return { kind: "gif", type: "image/gif", ext: "gif" };
  if (buf.toString("latin1", 4, 8) === "ftyp") return { kind: "video", type: "video/mp4", ext: "mp4" };
  if (buf.readUInt32BE(0) === 0x1a45dfa3) return { kind: "video", type: "video/webm", ext: "webm" };
  const head = buf.toString("utf8", 0, 512).trimStart().toLowerCase();
  if (head.startsWith("<svg") || (head.startsWith("<?xml") && head.includes("<svg"))) return { kind: "svg" };
  if (head.startsWith("<!doctype") || head.startsWith("<html") || head.includes("<head")) return { kind: "html" };
  return null;
}

// ---------------------------------------------------------------- public addresses only
const V4_PRIVATE = [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4]];
const v4n = (a) => a.split(".").reduce((n, x) => n * 256 + Number(x), 0);
export function isPublic(addr) {
  if (isIP(addr) === 4) return !V4_PRIVATE.some(([b, bits]) => (v4n(addr) >>> (32 - bits)) === (v4n(b) >>> (32 - bits)));
  if (isIP(addr) === 6) {
    const a = addr.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
    if (mapped) return isPublic(mapped[1]);
    return !(a === "::" || a === "::1" || /^f[cd]/.test(a) || /^fe[89ab]/.test(a) || /^ff/.test(a) || a.startsWith("64:ff9b:") || a.startsWith("2001:db8"));
  }
  return false;
}
// a DNS lookup that refuses private answers: the connection uses exactly what was checked
function publicLookup(host, opts, cb) {
  dnsLookup(host, { ...opts, all: true }, (err, list) => {
    if (err) return cb(err);
    const ok = (list || []).filter((x) => isPublic(x.address));
    if (!ok.length) return cb(Object.assign(new Error(`${host} is not a public address`), { code: "EPRIVATE" }));
    if (opts.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}
// GET with redirects (each checked), a size cap and a timeout -> {status, type, buf, url}
export function get(url, { max = MAX.image, ua = "Mozilla/5.0 (aegis-burrow backgrounds)", referer = null, timeout = 60000, hops = 5, lookup = publicLookup } = {}) {
  return new Promise((done, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new BackdropError("That isn't a link.")); }
    if (!/^https?:$/.test(u.protocol)) return reject(new BackdropError("Only http and https links."));
    if (isIP(u.hostname.replace(/^\[|\]$/g, "")) && !isPublic(u.hostname.replace(/^\[|\]$/g, ""))) return reject(new BackdropError("Links to private addresses aren't allowed."));
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.get(u, { lookup, timeout, headers: { "User-Agent": ua, Accept: "image/*,video/*,text/html;q=0.8,*/*;q=0.5", ...(referer ? { Referer: referer } : {}) } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (hops <= 0) return reject(new BackdropError("Too many redirects."));
        return get(new URL(res.headers.location, u).href, { max, ua, referer, timeout, hops: hops - 1, lookup }).then(done, reject);
      }
      const chunks = []; let got = 0;
      res.on("data", (c) => { got += c.length; if (got > max) { req.destroy(); reject(new BackdropError(`It is larger than ${Math.round(max / 1e6)} MB.`)); } else chunks.push(c); });
      res.on("end", () => done({ status: res.statusCode, type: String(res.headers["content-type"] || "").split(";")[0].trim(), buf: Buffer.concat(chunks), url: u.href }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new BackdropError("It took too long to download.")));
    req.on("error", (e) => reject(e instanceof BackdropError ? e : new BackdropError(e.code === "EPRIVATE" ? "Links to private addresses aren't allowed." : `Could not download it: ${e.code || e.message}`)));
  });
}

const WPF = /^https?:\/\/(?:www\.)?wallpaperflare\.com\/(?!search|static)([a-z0-9-]+-wallpaper-[a-z0-9]+)(?:\/download(?:\/[0-9x]+)?)?\/?(?:[?#].*)?$/i;
const attr = (tag, name) => new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, "i").exec(tag)?.[1] || null;
// A link -> {kind, type, ext, buf, name, source}. Pages are read for the picture they show.
export async function fetchLink(url, { getter = get } = {}) {
  url = String(url || "").trim();
  if (!/^https?:\/\/\S+$/i.test(url)) fail("Paste an http(s) link.");
  const named = (u) => decodeURIComponent(new URL(u).pathname.split("/").filter(Boolean).filter((x) => x !== "download").pop() || "Picture")
    .replace(/\.[a-z0-9]+$/i, "").replace(/-wallpaper-[a-z0-9]+$/i, "").replace(/[-_]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 60) || "Picture";
  let page = url;
  const w = WPF.exec(url);
  if (w) page = `https://www.wallpaperflare.com/${w[1]}/download`;
  let r = await getter(page, { max: w ? MAX.page : MAX.video, referer: w ? `https://www.wallpaperflare.com/${w[1]}` : null });
  if (r.status === 403 || r.status === 429 || r.status === 503) fail(w ? "wallpaperflare didn't let this machine download it (it asked for a browser check). Save the picture in your browser and upload the file instead." : `The site refused (HTTP ${r.status}). Save it in your browser and upload the file instead.`);
  if (r.status >= 400) fail(`The link answered HTTP ${r.status}.`);
  let s = sniff(r.buf);
  if (s?.kind === "html") {
    const html = r.buf.toString("utf8");
    let src = null;
    for (const tag of html.match(/<img\b[^>]*>/gi) || []) if (/\bid\s*=\s*["']show_img["']/i.test(tag)) { src = attr(tag, "src"); break; }
    src ||= /<meta[^>]+property=["']og:(?:video|image)(?::secure_url)?["'][^>]*>/i.exec(html)?.[0]?.match(/content=["']([^"']+)["']/i)?.[1] || null;
    if (!src) fail("That page doesn't show a picture this machine can find. Use the link to the picture itself (right-click it → Copy image address).");
    const pic = new URL(src.replace(/&amp;/g, "&"), r.url).href;
    r = await getter(pic, { max: MAX.video, referer: r.url });
    if (r.status >= 400) fail(`The picture answered HTTP ${r.status}.`);
    s = sniff(r.buf);
  }
  if (!s) fail("That isn't a picture, GIF or video this dashboard can show.");
  if (s.kind === "svg") fail("SVG pictures can carry scripts, so they can't be backgrounds. Use a PNG, JPEG, WebP, GIF or video.");
  if (s.kind === "html") fail("That link opens a web page, not a picture.");
  return { ...s, buf: r.buf, name: named(w ? `https://x/${w[1]}` : r.url), source: url };
}

// ---------------------------------------------------------------- the store
export class Backdrops {
  constructor(dir) { this.dir = dir; }
  index() { return join(this.dir, "index.json"); }
  list() {
    try { const v = JSON.parse(readFileSync(this.index(), "utf8")); return Array.isArray(v) ? v.filter((x) => ID.test(x?.id)).map((x) => ({ kind: "image", ...x })) : []; } catch { return []; }
  }
  save(list) {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const tmp = this.index() + ".tmp";
    writeFileSync(tmp, JSON.stringify(list, null, 1));
    renameSync(tmp, this.index());
  }
  static jpeg(v, max) {
    const b64 = String(v || "").replace(/^data:image\/jpeg;base64,/, "");
    if (!/^[A-Za-z0-9+/=\s]+$/.test(b64)) fail("A picture must be a JPEG.");
    const buf = Buffer.from(b64, "base64");
    if (buf.length < 100 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) fail("A picture must be a JPEG.");
    if (buf.length > max) fail("That picture is too big.");
    return buf;
  }
  room() { if (this.list().length >= LIMIT) fail(`Keep at most ${LIMIT} backgrounds: remove one first.`); }
  entry(fields) {
    const list = this.list();
    const e = { id: randomBytes(5).toString("hex"), name: String(fields.name || "Picture").replace(/[\u0000-\u001f]/g, "").trim().slice(0, 60) || "Picture",
                kind: fields.kind, ext: fields.ext || null, w: Math.max(0, Math.min(20000, Math.round(Number(fields.w) || 0))),
                h: Math.max(0, Math.min(20000, Math.round(Number(fields.h) || 0))), bytes: fields.bytes || 0,
                source: typeof fields.source === "string" && /^https?:\/\//.test(fields.source) ? fields.source.slice(0, 500) : null, poster: !!fields.poster, at: Date.now() };
    return { list, e };
  }
  // a picture the browser made sizes of
  add({ name, l, s, t, w, h, source } = {}) {
    this.room();
    const bufs = { l: Backdrops.jpeg(l, MAX.l), s: Backdrops.jpeg(s, MAX.s), t: Backdrops.jpeg(t, MAX.t) };
    const { list, e } = this.entry({ name, kind: "image", ext: "jpg", w, h, source, bytes: bufs.l.length + bufs.s.length, poster: true });
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    for (const k of ["l", "s", "t"]) writeFileSync(join(this.dir, `${e.id}-${k}.jpg`), bufs[k], { mode: 0o600 });
    list.unshift(e); this.save(list);
    return e;
  }
  // a GIF or a video, as it is
  addRaw(buf, { name, source, w, h } = {}) {
    this.room();
    const s = sniff(buf);
    if (!s || !["gif", "video"].includes(s.kind)) fail(s?.kind === "svg" ? "SVG pictures can't be backgrounds." : "Only GIFs and .mp4 or .webm videos are kept as they are; pictures are sized by your browser first.");
    if (buf.length > MAX[s.kind]) fail(`That ${s.kind === "gif" ? "GIF" : "video"} is larger than ${Math.round(MAX[s.kind] / 1e6)} MB.`);
    const { list, e } = this.entry({ name, kind: s.kind, ext: s.ext, w, h, source, bytes: buf.length });
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(this.dir, `${e.id}.${s.ext}`), buf, { mode: 0o600 });
    list.unshift(e); this.save(list);
    return e;
  }
  // the still a GIF or a video shows while it loads (and in pickers)
  poster(id, t, { w, h } = {}) {
    const list = this.list(), e = list.find((x) => x.id === id);
    if (!e) fail("No such background.");
    writeFileSync(join(this.dir, `${id}-t.jpg`), Backdrops.jpeg(t, MAX.t), { mode: 0o600 });
    e.poster = true;
    if (w && h && !e.w) { e.w = Math.round(w); e.h = Math.round(h); }
    this.save(list);
    return e;
  }
  rename(id, name) {
    const list = this.list(), e = list.find((x) => x.id === id);
    if (!e) fail("No such background.");
    e.name = String(name || "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, 60) || e.name;
    this.save(list);
    return e;
  }
  remove(id) {
    const list = this.list(), e = list.find((x) => x.id === id);
    if (!e) return false;
    this.save(list.filter((x) => x.id !== id));
    for (const f of [`${id}-l.jpg`, `${id}-s.jpg`, `${id}-t.jpg`, `${id}.gif`, `${id}.mp4`, `${id}.webm`]) { try { unlinkSync(join(this.dir, f)); } catch { /* gone */ } }
    return true;
  }
  // GET /__gate/backdrops/<id>-<l|s|t>.jpg, <id>.gif, <id>.mp4|webm -> {path, type} | null
  file(name) {
    const m = /^([a-z0-9][a-z0-9-]{0,39})(?:-([lst])\.jpg|\.(gif|mp4|webm))$/.exec(name || "");
    if (!m || !this.list().some((x) => x.id === m[1])) return null;
    const f = join(this.dir, name);
    if (!existsSync(f)) return null;
    return { path: f, type: m[2] ? "image/jpeg" : { gif: "image/gif", mp4: "video/mp4", webm: "video/webm" }[m[3]] };
  }
}
