// File types a tunnel won't let through (t.blockTypes = {list, dir}).
//
//   list   "gif", ".mp4", "image/gif", "video/*"   extensions or MIME types
//   dir    "out"  what the tunnel sends to visitors (downloads, images, pages)
//          "in"   what visitors send through it (uploads)
//          "both"
//
// Out is judged on the response's Content-Type, its Content-Disposition file
// name and the address's extension; in, on the request's Content-Type, the
// address's extension, and each part of a form upload (its file name and
// type, read as the upload streams by). An extension blocks its MIME types
// too: "gif" stops image/gif whatever the address says.

const MIME = {
  gif: ["image/gif"], png: ["image/png"], jpg: ["image/jpeg"], jpeg: ["image/jpeg"], webp: ["image/webp"], avif: ["image/avif"],
  svg: ["image/svg+xml"], ico: ["image/x-icon", "image/vnd.microsoft.icon"], bmp: ["image/bmp"], heic: ["image/heic"], tiff: ["image/tiff"],
  mp4: ["video/mp4"], webm: ["video/webm", "audio/webm"], mov: ["video/quicktime"], mkv: ["video/x-matroska"], avi: ["video/x-msvideo"], m3u8: ["application/vnd.apple.mpegurl", "application/x-mpegurl"],
  mp3: ["audio/mpeg"], wav: ["audio/wav", "audio/x-wav"], ogg: ["audio/ogg", "video/ogg"], flac: ["audio/flac"], m4a: ["audio/mp4"],
  pdf: ["application/pdf"], zip: ["application/zip", "application/x-zip-compressed"], rar: ["application/vnd.rar", "application/x-rar-compressed"],
  "7z": ["application/x-7z-compressed"], tar: ["application/x-tar"], gz: ["application/gzip", "application/x-gzip"],
  exe: ["application/x-msdownload", "application/vnd.microsoft.portable-executable"], msi: ["application/x-msi"], apk: ["application/vnd.android.package-archive"],
  dmg: ["application/x-apple-diskimage"], iso: ["application/x-iso9660-image"], jar: ["application/java-archive"],
  doc: ["application/msword"], docx: ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  xls: ["application/vnd.ms-excel"], xlsx: ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  ppt: ["application/vnd.ms-powerpoint"], pptx: ["application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  js: ["text/javascript", "application/javascript"], css: ["text/css"], html: ["text/html"], htm: ["text/html"], json: ["application/json"],
  txt: ["text/plain"], csv: ["text/csv"], xml: ["application/xml", "text/xml"], wasm: ["application/wasm"], swf: ["application/x-shockwave-flash"],
  woff: ["font/woff"], woff2: ["font/woff2"], ttf: ["font/ttf"], otf: ["font/otf"],
};
// What every site is made of: pages, styles, scripts, data, fonts. These always
// get through, whatever the list says (blocking them takes the whole site down,
// and the gate's own sign-in with it), and a list that names them skips them.
const CORE_EXT = new Set(["html", "htm", "xhtml", "css", "js", "mjs", "cjs", "json", "map", "webmanifest", "woff", "woff2", "ttf", "otf", "txt", "xml"]);
const CORE_MIME = new Set(["text/html", "application/xhtml+xml", "text/css", "text/javascript", "application/javascript", "application/x-javascript",
  "application/json", "application/manifest+json", "text/plain", "text/xml", "application/xml", "font/woff", "font/woff2", "font/ttf", "font/otf",
  "application/x-www-form-urlencoded", "text/event-stream", "application/grpc", "application/x-ndjson"]);
const isCoreMime = (m) => CORE_MIME.has(m) || m.startsWith("font/") || m.endsWith("+json");
export const isCore = (x) => (x.includes("/") ? isCoreMime(x) : CORE_EXT.has(x));
const EXT_RE = /^[a-z0-9][a-z0-9+-]{0,15}$/, MIME_RE = /^[a-z]+\/(?:\*|[a-z0-9][a-z0-9.+-]{0,80})$/;

// what people type -> {list, dir} (or null: nothing blocked)
export function cleanBlock(v) {
  if (v == null || v === "" || v === false) return null;
  const raw = Array.isArray(v) ? v : Array.isArray(v.list) ? v.list : String(v.list ?? v).split(/[\s,;]+/);
  const list = [];
  for (let x of raw) {
    x = String(x || "").trim().toLowerCase().replace(/^\*?\./, "");
    if (!x) continue;
    if (isCore(x) || x === "*/*") continue;          // always let through (see CORE_*)
    if (!EXT_RE.test(x) && !MIME_RE.test(x)) throw new Error(`"${x}" isn't a file type: use an extension like gif, or a type like image/gif or video/*.`);
    if (!list.includes(x)) list.push(x);
  }
  if (list.length > 60) throw new Error("That's a lot of file types (60 at most).");
  if (!list.length) return null;
  const dir = ["in", "out", "both"].includes(v?.dir) ? v.dir : "both";
  return { list, dir };
}

const extOf = (name) => { const m = /\.([a-z0-9+-]{1,16})$/i.exec(String(name || "").split(/[?#]/)[0]); return m ? m[1].toLowerCase() : ""; };
const mimeOf = (ct) => String(ct || "").split(";")[0].trim().toLowerCase();

// the first entry that matches {path, type, name}, or null
export function blockedBy(rules, { path, type, name }) {
  if (!rules?.list?.length) return null;
  let p = "";
  try { p = decodeURIComponent(String(path || "").split("?")[0]); } catch { p = String(path || "").split("?")[0]; }
  const exts = [extOf(p), extOf(name)].filter(Boolean), mime = mimeOf(type);
  // a page, style, script, data or font is never stopped (a saved list from 2.32.0 may still name them)
  if (mime && isCoreMime(mime)) return null;
  if (!mime && exts.length && exts.every((e) => CORE_EXT.has(e))) return null;
  for (const r of rules.list) {
    if (isCore(r)) continue;
    if (r.includes("/")) {
      if (mime && (r.endsWith("/*") ? mime.startsWith(r.slice(0, -1)) : mime === r)) return r;
      // a MIME rule also stops the extensions it's known by (image/gif stops x.gif)
      if (exts.some((e) => (MIME[e] || []).some((m) => (r.endsWith("/*") ? m.startsWith(r.slice(0, -1)) : m === r)))) return r;
    } else {
      if (exts.includes(r)) return r;
      if (mime && (MIME[r] || []).includes(mime)) return r;
    }
  }
  return null;
}
export const blocksOut = (rules) => !!rules && rules.dir !== "in";
export const blocksIn = (rules) => !!rules && rules.dir !== "out";

// a file name from Content-Disposition (filename*=UTF-8''x.gif or filename="x.gif")
export function dispositionName(cd) {
  const s = String(cd || "");
  const star = /filename\*\s*=\s*[^']*'[^']*'([^;]+)/i.exec(s);
  if (star) { try { return decodeURIComponent(star[1].trim()); } catch { return star[1].trim(); } }
  const m = /filename\s*=\s*"([^"]*)"|filename\s*=\s*([^;\s]+)/i.exec(s);
  return m ? (m[1] ?? m[2]) : "";
}

// Watches a form upload (multipart) as it streams: each part's file name and
// type. feed(chunk) -> the rule it broke, or null. Part headers can be split
// across chunks: the end of the last chunk is kept and looked at again.
export function uploadWatch(rules) {
  let tail = "";
  return (chunk) => {
    const s = tail + chunk.toString("latin1");
    tail = s.slice(-1024);
    const re = /content-disposition:[^\r\n]*?filename\*?=\s*(?:[^']*''|")?([^"\r\n;]*)"?[^\r\n]*(?:\r?\n(?:content-type:\s*([^\r\n]+)))?/gi;
    let m;
    while ((m = re.exec(s))) {
      const hit = blockedBy(rules, { name: m[1], type: m[2] || "" });
      if (hit) return hit;
    }
    const ct = /\r?\ncontent-type:\s*([^\r\n]+)\r?\n\r?\n/gi;
    while ((m = ct.exec(s))) { const hit = blockedBy(rules, { type: m[1] }); if (hit) return hit; }
    return null;
  };
}
