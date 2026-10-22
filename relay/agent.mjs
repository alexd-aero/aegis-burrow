// Aegis Relay agent: the small program on your VPS that carries your tunnels
// to your Aegis at home, and nothing else.
//
//   visitors ──TLS──▶ this VPS (Caddy, or the agent itself on :443)
//            ──▶ agent ──signed request──▶ 127.0.0.1:UPSTREAM  (a reverse SSH tunnel
//                                          that only your Aegis can open, as the
//                                          locked-down user aegis-relay)
//            ──▶ your Aegis, which checks the signature before anything else
//
// Every request is signed with a key only this agent and your Aegis hold
// (HMAC-SHA256 over a timestamp, a one-time nonce, the host, the visitor's
// address, the method and the path). Nothing else on this server can feed
// requests to your Aegis, and nothing can claim to be another visitor.
// The certificates (*.<your tunnel zone>, Let's Encrypt, renewed by your Aegis)
// come over the same tunnel, signed the same way: the first zone's from the
// install, and one per domain your Aegis adds later (POST /cert with its suffix;
// the list is kept in zones.json next to the config). Only names one level under
// those zones are served; everything else gets 421. Your Aegis can also send a
// newer agent (POST /update, signed): it is checked with `node --check`, takes
// this file's place, and systemd starts it again. And it can link this server
// into your Aegis's Machines (POST /fleet/link, signed): the same link script
// any machine runs, run here as root, so a VPS added for the tunnels is a
// machine like any other without a second command (agent 1.4+). Neither gives
// your Aegis more than /update already did.
//
// Public tunnels are checked here first (POST /edge from your Aegis: which names
// are public, which addresses a scan cleared or are yours, which are banned):
// someone new gets a "checking your connection" page from this server while a
// signed one-line "scan this address" goes home, and their request reaches your
// Aegis only once the scan cleared them. Banned addresses are turned away here
// too. A request with a device key is passed on: only your Aegis can tell a
// real one, and it does.
//
// One file, no dependencies, Node 18+. Config: /etc/aegis-relay/config.json.
// Installed by the one-line command your Aegis shows (Settings → Domain).

import { createServer as httpServer, request as httpRequest } from "node:http";
import { createServer as httpsServer } from "node:https";
import { createSecureContext } from "node:tls";
import { createHmac, randomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, chmodSync, chownSync, statSync, rmSync } from "node:fs";
import { execFile, execFileSync } from "node:child_process";
import { join, dirname } from "node:path";

export const VERSION = "1.4.0";
export const FEATURES = ["zones", "update", "edge", "fleet"];
const SUFFIX_RE = /^(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,63}$/;
const CONFIG = process.env.AEGIS_RELAY_CONFIG || "/etc/aegis-relay/config.json";

// ------------------------------------------------------------------ the signature (same as Aegis's relaylink.mjs)
export function sign(key, { host, ip, method, url, ts = Date.now(), nonce = randomBytes(12).toString("base64url") }) {
  const mac = createHmac("sha256", key).update(`v1\n${ts}\n${nonce}\n${host}\n${ip}\n${method}\n${url}`).digest("base64url");
  return `v1.${ts}.${nonce}.${mac}`;
}
const seen = new Map();
export function verify(key, header, { host, ip, method, url }, now = Date.now()) {
  const m = /^v1\.(\d{10,16})\.([A-Za-z0-9_-]{8,40})\.([A-Za-z0-9_-]{43})$/.exec(String(header || ""));
  if (!m) return false;
  const ts = Number(m[1]);
  if (Math.abs(now - ts) > 60e3) return false;
  const want = createHmac("sha256", key).update(`v1\n${ts}\n${m[2]}\n${host}\n${ip}\n${method}\n${url}`).digest();
  const got = Buffer.from(m[3], "base64url");
  if (got.length !== want.length || !timingSafeEqual(got, want)) return false;
  if (seen.has(m[2])) return false;                                  // replayed
  seen.set(m[2], ts);
  if (seen.size > 20000) for (const [n, t] of seen) { if (now - t > 120e3) seen.delete(n); if (seen.size < 10000) break; }
  return true;
}

// ------------------------------------------------------------------ the pages a visitor may get instead
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
// kind "checking" (a scan is on its way; it reloads by itself) or "blocked"
export function visitorPage(kind, { ip = "", retry = 2 } = {}) {
  const checking = kind === "checking";
  const title = checking ? "Checking your connection" : "Access blocked";
  const text = checking
    ? "This site checks every new visitor's address before letting it through. Yours is being checked right now; this page reloads by itself in a moment."
    : "This site's protection blocked your address. If you think that's a mistake, tell the site's owner the address and time below.";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${checking ? `<meta http-equiv="refresh" content="${Number(retry) || 2}">` : ""}<meta name="robots" content="noindex"><title>${title}</title>
<style>:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#030304;color:#e8eaed;font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px;box-sizing:border-box}
.c{max-width:420px;width:100%;padding:28px 28px 22px;border:1px solid rgba(255,255,255,.1);border-radius:18px;background:#0f1012;box-sizing:border-box}
.i{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;margin-bottom:16px;border:1px solid ${checking ? "rgba(122,167,255,.35);background:rgba(122,167,255,.08);color:#7aa7ff" : "rgba(255,90,82,.35);background:rgba(255,90,82,.08);color:#ff5a52"}}
.i svg{width:22px;height:22px}${checking ? ".i svg{animation:s 1.1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}" : ""}
h1{font-size:18px;margin:0 0 6px;letter-spacing:-.01em}p{margin:0;color:#8a8f97}dl{margin:18px 0 0;padding-top:14px;border-top:1px solid rgba(255,255,255,.08);display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font:12px ui-monospace,Menlo,Consolas,monospace;color:#8a8f97}dt{color:#555a62}dd{margin:0;overflow-wrap:anywhere}</style></head>
<body><main class="c"><div class="i">${checking ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.56"/></svg>' : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>'}</div>
<h1>${title}</h1><p>${text}</p><dl><dt>Address</dt><dd>${esc(ip)}</dd><dt>Time</dt><dd>${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</dd></dl></main></body></html>`;
}

// ------------------------------------------------------------------ the agent
export function startAgent(cfg, { log = (...a) => console.log(new Date().toISOString(), ...a) } = {}) {
  const key = Buffer.from(cfg.key, "base64url");
  const suffix = String(cfg.suffix).toLowerCase();                    // ".tunnel.example.com": the first zone, from the install
  const stats = { requests: 0, ws: 0, refused: 0, upstreamErrors: 0, edgeChecks: 0, edgeBlocked: 0, since: Date.now(), lastOk: 0 };
  const certFile = join(cfg.certDir, "tunnel.crt"), keyFile = join(cfg.certDir, "tunnel.key");
  // every zone: the first one, and the ones your Aegis added since (zones.json)
  const zonesFile = cfg.zonesFile || join(dirname(cfg.certDir), "zones.json");
  let extra = [];
  try { extra = JSON.parse(readFileSync(zonesFile, "utf8")).filter((z) => SUFFIX_RE.test(z) && z !== suffix); } catch { /* none yet */ }
  const zones = () => [suffix, ...extra];
  const filesOf = (z) => z === suffix ? { crt: certFile, key: keyFile } : { crt: join(cfg.certDir, `z${z}.crt`), key: join(cfg.certDir, `z${z}.key`) };
  const saveZones = () => { mkdirSync(dirname(zonesFile), { recursive: true }); writeFileSync(zonesFile + ".tmp", JSON.stringify(extra)); renameSync(zonesFile + ".tmp", zonesFile); };
  const zoneOf = (host) => {
    host = String(host || "").toLowerCase().replace(/:\d+$/, "");
    let best = null;
    for (const z of zones()) if (host.endsWith(z) && host.length > z.length && !host.slice(0, -z.length).includes(".") && (!best || z.length > best.length)) best = z;
    return best;
  };
  const ours = (host) => (zoneOf(host) ? String(host).toLowerCase().replace(/:\d+$/, "") : null);

  // the visitor's address: Caddy in front says it in x-aegis-client (only believed from this machine)
  const visitor = (req) => {
    const peer = String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
    if (cfg.mode === "caddy") return /^(127\.|::1$)/.test(peer) ? String(req.headers["x-aegis-client"] || "").split(",")[0].trim() || null : null;
    return peer;
  };
  const upstreamHeaders = (req, host, ip) => {
    const h = {};
    for (const [k, v] of Object.entries(req.headers)) if (!/^(x-aegis-|cf-connecting-ip$|x-forwarded-|x-real-ip$|true-client-ip$|forwarded$)/i.test(k)) h[k] = v;
    h.host = host;
    h["x-aegis-relay-ip"] = ip;
    h["x-aegis-relay"] = sign(key, { host, ip, method: req.method, url: req.url });
    return h;
  };
  // public tunnels, checked here first (POST /edge)
  let edge = { on: false, epoch: null, hosts: new Set(), cleared: new Set(), banned: new Set() };
  const pinged = new Map();                                            // ip -> when home was asked to scan it
  const DEVICE_RE = /(?:^|;\s*)(?:__Host-)?aegis-dev=/;
  const scanPing = (ip) => {
    const last = pinged.get(ip) || 0;
    if (Date.now() - last < 5000) return;
    pinged.set(ip, Date.now());
    if (pinged.size > 20000) for (const [k, t] of pinged) { if (Date.now() - t > 60e3) pinged.delete(k); if (pinged.size < 10000) break; }
    const url = "/__aegis-relay/scan";
    const r = httpRequest({ host: "127.0.0.1", port: cfg.upstreamPort, method: "POST", path: url, timeout: 10000,
      headers: { host: "scan", "x-aegis-relay-ip": ip, "x-aegis-relay": sign(key, { host: "scan", ip, method: "POST", url }), "content-length": 0 } }, (res) => res.resume());
    r.on("timeout", () => r.destroy()); r.on("error", () => {});
    r.end();
  };
  // -> null (on to your Aegis) or "checking" / "blocked"
  const edgeStop = (req, host, ip) => {
    if (DEVICE_RE.test(String(req.headers.cookie || ""))) return null;       // a device key: your Aegis checks it
    if (edge.banned.has(ip)) { stats.edgeBlocked++; return "blocked"; }
    if (edge.on && edge.hosts.has(host) && !edge.cleared.has(ip)) { stats.edgeChecks++; scanPing(ip); return "checking"; }
    return null;
  };
  const turnAway = (res, kind, ip) => {
    res.writeHead(403, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...(kind === "checking" ? { "Retry-After": "2" } : {}) });
    res.end(visitorPage(kind, { ip }));
  };
  const offline = (res) => {
    res.writeHead(502, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Not connected</title><body style="margin:0;display:grid;place-items:center;min-height:100vh;background:#0b0c0e;color:#e8eaed;font:15px system-ui,sans-serif"><div style="max-width:380px;padding:24px"><h1 style="font-size:18px">The home end isn\'t connected</h1><p style="color:#8a8f97">This relay is up, but the Aegis it carries isn\'t connected to it right now. Try again in a minute.</p></div>');
  };

  function onRequest(req, res) {
    const host = ours(req.headers.host), ip = visitor(req);
    if (!host || !ip) { stats.refused++; res.writeHead(421, { "Content-Type": "text/plain" }); return res.end("Misdirected request"); }
    const stop = edgeStop(req, host, ip);
    if (stop) return turnAway(res, stop, ip);
    stats.requests++;
    const up = httpRequest({ host: "127.0.0.1", port: cfg.upstreamPort, method: req.method, path: req.url, headers: upstreamHeaders(req, host, ip), timeout: 120000 }, (upRes) => {
      stats.lastOk = Date.now();
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    up.on("timeout", () => up.destroy(new Error("timeout")));
    up.on("error", () => { stats.upstreamErrors++; if (!res.headersSent) offline(res); else res.destroy(); });
    req.pipe(up);
  }
  function onUpgrade(req, socket, head) {
    const host = ours(req.headers.host), ip = visitor(req);
    if (!host || !ip) { stats.refused++; return socket.end("HTTP/1.1 421 Misdirected Request\r\n\r\n"); }
    if (edgeStop(req, host, ip)) return socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    stats.ws++;
    const up = httpRequest({ host: "127.0.0.1", port: cfg.upstreamPort, method: req.method, path: req.url, headers: upstreamHeaders(req, host, ip) });
    up.on("upgrade", (upRes, upSock, upHead) => {
      const lines = [`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}`];
      for (let i = 0; i < upRes.rawHeaders.length; i += 2) lines.push(`${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}`);
      socket.write(lines.join("\r\n") + "\r\n\r\n");
      if (upHead?.length) socket.write(upHead);
      if (head?.length) upSock.write(head);
      upSock.pipe(socket).pipe(upSock);
      socket.on("error", () => upSock.destroy()); upSock.on("error", () => socket.destroy());
    });
    up.on("response", (upRes) => { socket.end(`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n\r\n`); });
    up.on("error", () => { stats.upstreamErrors++; socket.destroy(); });
    up.end();
  }

  // the visitors' side: behind Caddy (plain HTTP on loopback), or TLS on :443 itself
  const ctxs = new Map();               // zone -> TLS context
  const loadCtx = () => {
    ctxs.clear();
    for (const z of zones()) {
      const f = filesOf(z);
      try { if (existsSync(f.crt)) ctxs.set(z, createSecureContext({ cert: readFileSync(f.crt), key: readFileSync(f.key), minVersion: "TLSv1.2" })); } catch (e) { log(`certificate for *${z}:`, e.message); }
    }
  };
  loadCtx();
  const front = cfg.mode === "tls"
    ? httpsServer({ SNICallback: (name, cb) => { const c = ctxs.get(zoneOf(name)); c ? cb(null, c) : cb(new Error("not ours")); }, minVersion: "TLSv1.2" }, onRequest)
    : httpServer(onRequest);
  front.on("upgrade", onUpgrade);
  front.on("tlsClientError", () => {});
  front.keepAliveTimeout = 65000;
  front.listen(cfg.mode === "tls" ? cfg.tlsPort || 443 : cfg.httpPort, cfg.mode === "tls" ? "0.0.0.0" : "127.0.0.1",
               () => log(`aegis relay agent ${VERSION}: ${cfg.mode === "tls" ? "TLS on :" + (cfg.tlsPort || 443) : "behind Caddy on 127.0.0.1:" + cfg.httpPort} -> 127.0.0.1:${cfg.upstreamPort}, names ${zones().map((z) => "*" + z).join(" ")}`));

  // the certificate, as Caddy wants it (files + a site), or for the agent's own TLS
  // one site block per zone that has its certificate. TLS 1.3 only, post-quantum key
  // exchange first. HTTP/2 only: Caddy offers HTTP/3 (QUIC, over UDP) to every site,
  // and through the relay it crawled where UDP is throttled (a 3.8 MB file took 23 s,
  // ~1 s over HTTP/2), so these names tell browsers to forget it (Alt-Svc: clear).
  function caddySite() {
    const have = zones().filter((z) => z === suffix || existsSync(filesOf(z).crt));
    return `# Aegis Relay: ${have.map((z) => "*" + z).join(", ")} -> the Aegis at home, through the relay agent (written by it; don't edit)
` + have.map((z) => `*${z} {
	tls ${filesOf(z).crt} ${filesOf(z).key} {
		protocols tls1.3
		curves x25519mlkem768 x25519 secp256r1
	}
	header -Server
	header Alt-Svc clear
	reverse_proxy 127.0.0.1:${cfg.httpPort} {
		header_up X-Aegis-Client {remote_host}
	}
}
`).join("\n");
  }
  // Caddy: our site file, imported by the Caddyfile (a glob over its folder, or a line of
  // its own; an older hand-made site's import line becomes ours), checked with
  // `caddy validate` before the reload, and everything put back if it doesn't pass.
  // an agent that updated itself brings its site up to date (once, and only if Caddy takes it)
  if (cfg.mode === "caddy" && cfg.caddySite && existsSync(cfg.caddySite) && readFileSync(cfg.caddySite, "utf8") !== caddySite()) {
    try { caddyInstall(); log("the relay's Caddy site is up to date"); } catch (e) { log(e.message); }
  }
  function caddyInstall() {
    const site = cfg.caddySite, cf = cfg.caddyfile || "/etc/caddy/Caddyfile";
    const undo = [];
    const keep = (f) => { if (existsSync(f)) { const b = readFileSync(f); undo.push(() => writeFileSync(f, b)); } else undo.push(() => { try { renameSync(f, f + ".failed"); } catch { /* gone */ } }); };
    try {
      if (existsSync(cf)) {
        let text = readFileSync(cf, "utf8");
        const before = text;
        if (cfg.replaces) text = text.split("\n").map((l) => (l.trim() === `import ${cfg.replaces}` ? l.replace(cfg.replaces, site) : l)).join("\n");
        const dir = dirname(site), covered = text.includes(site) || new RegExp(`import\\s+${dir.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}/\\*`).test(text);
        if (!covered) text = text.replace(/\n*$/, `\n\nimport ${site}\n`);
        if (text !== before) { keep(cf); writeFileSync(cf, text); }
      }
      if (cfg.replaces && existsSync(cfg.replaces)) {
        const old = cfg.replaces;
        renameSync(old, old + ".before-aegis-relay");
        undo.push(() => renameSync(old + ".before-aegis-relay", old));
        log("moved aside", old);
      }
      if (!existsSync(site) || readFileSync(site, "utf8") !== caddySite()) { keep(site); mkdirSync(dirname(site), { recursive: true }); writeFileSync(site, caddySite()); }
      if (cfg.reload === false) return;
      execFileSync("caddy", ["validate", "--config", cf, "--adapter", "caddyfile"], { stdio: "pipe", timeout: 30000 });
    } catch (e) {
      for (const u of undo.reverse()) { try { u(); } catch { /* best effort */ } }
      const why = String(e.stderr || e.message).split("\n").filter(Boolean).pop();
      log("caddy didn't accept the change, put back as it was:", why);
      throw new Error(`Caddy didn't accept the relay's site (${why}); nothing was changed`);
    }
    execFile("systemctl", ["reload", "caddy"], (e) => log(e ? `caddy reload failed: ${e.message}` : "caddy reloaded with the new certificate"));
  }
  function installCert(cert, privKey, z = suffix) {
    const x = new X509Certificate(cert);
    mkdirSync(cfg.certDir, { recursive: true });
    const f = filesOf(z), added = z !== suffix && !extra.includes(z);
    const old = [f.crt, f.key].map((p) => (existsSync(p) ? readFileSync(p) : null));
    const write = (file, data, mode) => { writeFileSync(file + ".tmp", data, { mode }); renameSync(file + ".tmp", file); chmodSync(file, mode); };
    write(f.crt, cert, 0o644);
    write(f.key, privKey, 0o640);
    if (cfg.caddyGroup !== undefined) { try { chownSync(f.key, 0, cfg.caddyGroup); } catch { /* not root: tests */ } }
    if (added) { extra.push(z); saveZones(); }
    try { if (cfg.mode === "caddy") caddyInstall(); }
    catch (e) {           // Caddy said no: this zone's files as they were
      [f.crt, f.key].forEach((p, i) => { try { old[i] ? writeFileSync(p, old[i]) : rmSync(p, { force: true }); } catch { /* best effort */ } });
      if (added) { extra = extra.filter((x) => x !== z); saveZones(); }
      throw e;
    }
    loadCtx();
    log(`certificate for ${x.subjectAltName} until ${x.validTo}`);
    return { fingerprint: x.fingerprint256, notAfter: Date.parse(x.validTo) };
  }
  function removeZone(z) {
    if (z === suffix) throw new Error("that's the first zone; reinstall to change it");
    if (!extra.includes(z)) return false;
    extra = extra.filter((x) => x !== z); saveZones();
    const f = filesOf(z);
    rmSync(f.crt, { force: true }); rmSync(f.key, { force: true });
    if (cfg.mode === "caddy") caddyInstall();
    loadCtx();
    log(`no longer serving *${z}`);
    return true;
  }
  const certInfo = (z) => { try { const x = new X509Certificate(readFileSync(filesOf(z).crt)); return { fingerprint: x.fingerprint256, notAfter: Date.parse(x.validTo), names: x.subjectAltName }; } catch { return null; } };

  // the control side: only through the tunnel, only signed by your Aegis
  const control = httpServer((req, res) => {
    const reply = (status, obj) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (!verify(key, req.headers["x-aegis-relay"], { host: "agent", ip: "-", method: req.method, url: req.url })) return reply(401, { error: "not signed by your Aegis" });
    if (req.method === "GET" && req.url === "/status") {
      return reply(200, { version: VERSION, features: FEATURES, mode: cfg.mode, suffix, cert: certInfo(suffix),
                          zones: zones().map((z) => ({ suffix: z, cert: certInfo(z) })), stats,
                          edge: { on: edge.on, epoch: edge.epoch, hosts: edge.hosts.size, cleared: edge.cleared.size, banned: edge.banned.size } });
    }
    const body = (max, fn) => {
      let b = "";
      req.on("data", (d) => { b += d; if (b.length > max) req.destroy(); });
      req.on("end", () => { try { fn(JSON.parse(b || "{}")); } catch (e) { reply(400, { error: e.message }); } });
    };
    if (req.method === "POST" && req.url === "/cert") {
      return body(64 * 1024, ({ cert, key: k, suffix: z = suffix }) => {
        z = String(z).toLowerCase();
        if (!SUFFIX_RE.test(z)) return reply(400, { error: "that isn't a zone" });
        const x = new X509Certificate(cert);
        if (!x.subjectAltName.split(", ").some((n) => n === `DNS:*${z}`)) return reply(400, { error: `that certificate isn't for *${z}` });
        reply(200, { ok: true, suffix: z, ...installCert(cert, k, z) });
      });
    }
    // who may pass: in full ({full, epoch, on, hosts, cleared, banned}), or what changed since
    // ({epoch, on?, hosts?, add: {cleared, banned}, del: {cleared, banned}}); 409 when this agent lost the thread
    if (req.method === "POST" && req.url === "/edge") {
      return body(16 * 1024 * 1024, (b) => {
        const list = (x) => (Array.isArray(x) ? x.map(String) : []);
        if (b.full) edge = { on: !!b.on, epoch: String(b.epoch || ""), hosts: new Set(list(b.hosts).map((x) => x.toLowerCase())), cleared: new Set(list(b.cleared)), banned: new Set(list(b.banned)) };
        else {
          if (!edge.epoch || b.epoch !== edge.epoch) return reply(409, { error: "send it in full", epoch: edge.epoch });
          if ("on" in b) edge.on = !!b.on;
          if (b.hosts) edge.hosts = new Set(list(b.hosts).map((x) => x.toLowerCase()));
          for (const k of ["cleared", "banned"]) { for (const ip of list(b.add?.[k])) edge[k].add(ip); for (const ip of list(b.del?.[k])) edge[k].delete(ip); }
        }
        reply(200, { ok: true, epoch: edge.epoch, on: edge.on, hosts: edge.hosts.size, cleared: edge.cleared.size, banned: edge.banned.size });
      });
    }
    if (req.method === "POST" && req.url === "/zones/remove") {
      return body(4096, ({ suffix: z }) => reply(200, { ok: true, removed: removeZone(String(z || "").toLowerCase()) }));
    }
    // a newer agent from your Aegis: checked, then it takes this file's place, and systemd starts it
    if (req.method === "POST" && req.url === "/update") {
      return body(2 * 1024 * 1024, ({ code, version }) => {
        if (typeof code !== "string" || !code.includes("startAgent")) return reply(400, { error: "that isn't an agent" });
        const self = cfg.agentFile || new URL(import.meta.url).pathname, next = self.replace(/\.m?js$/, "") + ".next.mjs";
        writeFileSync(next, code, { mode: 0o644 });
        try { execFileSync(process.execPath, ["--check", next], { stdio: "pipe", timeout: 30000 }); }
        catch (e) { rmSync(next, { force: true }); const lines = String(e.stderr || e.message).split("\n"); return reply(400, { error: "it doesn't parse: " + (lines.find((l) => /Error/.test(l)) || lines[0]) }); }
        if (existsSync(self)) writeFileSync(self + ".prev", readFileSync(self));
        renameSync(next, self);
        log(`updated to ${String(version || "?").slice(0, 20)}; restarting`);
        reply(200, { ok: true, from: VERSION, to: version || null });
        if (cfg.exitOnUpdate !== false) setTimeout(() => process.exit(0), 300);
      });
    }
    // into your Aegis's Machines: its link script, as root ({script}; -> {code, out})
    if (req.method === "POST" && req.url === "/fleet/link") {
      return body(512 * 1024, ({ script }) => {
        if (typeof script !== "string" || !script.startsWith("#!/bin/sh")) return reply(400, { error: "that isn't a link script" });
        const env = { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: "/root", LANG: "C.UTF-8", AEGIS_FROM_RELAY: "1" };
        const child = execFile("sh", ["-s"], { env, cwd: "/", timeout: 280000, maxBuffer: 4 * 1024 * 1024 }, (e, out, err) => {
          const text = `${out || ""}${err || ""}`.slice(-6000);
          log(`linked into Machines: ${e ? "failed (" + (e.code ?? e.signal) + ")" : "done"}`);
          reply(200, { ok: !e, code: e ? e.code ?? -1 : 0, out: text });
        });
        child.stdin.on("error", () => {});
        child.stdin.end(script);
      });
    }
    reply(404, { error: "not found" });
  });
  control.listen(cfg.controlPort, "127.0.0.1");
  return { front, control, stats, installCert, removeZone, zones, close: () => { front.close(); control.close(); } };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
  startAgent(cfg);
}
