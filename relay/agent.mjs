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
// The certificate (*.<your tunnel zone>, Let's Encrypt, renewed by your Aegis)
// comes over the same tunnel, signed the same way. Only names under that zone
// are served; everything else gets 421.
//
// One file, no dependencies, Node 18+. Config: /etc/aegis-relay/config.json.
// Installed by the one-line command your Aegis shows (Settings → Domain).

import { createServer as httpServer, request as httpRequest } from "node:http";
import { createServer as httpsServer } from "node:https";
import { createSecureContext } from "node:tls";
import { createHmac, randomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, chmodSync, chownSync, statSync } from "node:fs";
import { execFile } from "node:child_process";
import { join, dirname } from "node:path";

export const VERSION = "1.0.0";
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

// ------------------------------------------------------------------ the agent
export function startAgent(cfg, { log = (...a) => console.log(new Date().toISOString(), ...a) } = {}) {
  const key = Buffer.from(cfg.key, "base64url");
  const suffix = String(cfg.suffix).toLowerCase();                    // ".tunnel.example.com"
  const stats = { requests: 0, ws: 0, refused: 0, upstreamErrors: 0, since: Date.now(), lastOk: 0 };
  const certFile = join(cfg.certDir, "tunnel.crt"), keyFile = join(cfg.certDir, "tunnel.key");
  const ours = (host) => { host = String(host || "").toLowerCase().replace(/:\d+$/, ""); return host.endsWith(suffix) && host.length > suffix.length && !host.slice(0, -suffix.length).includes(".") ? host : null; };

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
  const offline = (res) => {
    res.writeHead(502, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Not connected</title><body style="margin:0;display:grid;place-items:center;min-height:100vh;background:#0b0c0e;color:#e8eaed;font:15px system-ui,sans-serif"><div style="max-width:380px;padding:24px"><h1 style="font-size:18px">The home end isn\'t connected</h1><p style="color:#8a8f97">This relay is up, but the Aegis it carries isn\'t connected to it right now. Try again in a minute.</p></div>');
  };

  function onRequest(req, res) {
    const host = ours(req.headers.host), ip = visitor(req);
    if (!host || !ip) { stats.refused++; res.writeHead(421, { "Content-Type": "text/plain" }); return res.end("Misdirected request"); }
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
  let ctx = null;
  const loadCtx = () => { try { ctx = existsSync(certFile) ? createSecureContext({ cert: readFileSync(certFile), key: readFileSync(keyFile), minVersion: "TLSv1.2" }) : null; } catch (e) { log("certificate:", e.message); ctx = null; } };
  loadCtx();
  const front = cfg.mode === "tls"
    ? httpsServer({ SNICallback: (name, cb) => (ours(name) && ctx ? cb(null, ctx) : cb(new Error("not ours"))), minVersion: "TLSv1.2" }, onRequest)
    : httpServer(onRequest);
  front.on("upgrade", onUpgrade);
  front.on("tlsClientError", () => {});
  front.keepAliveTimeout = 65000;
  front.listen(cfg.mode === "tls" ? cfg.tlsPort || 443 : cfg.httpPort, cfg.mode === "tls" ? "0.0.0.0" : "127.0.0.1",
               () => log(`aegis relay agent ${VERSION}: ${cfg.mode === "tls" ? "TLS on :" + (cfg.tlsPort || 443) : "behind Caddy on 127.0.0.1:" + cfg.httpPort} -> 127.0.0.1:${cfg.upstreamPort}, names *${suffix}`));

  // the certificate, as Caddy wants it (files + a site), or for the agent's own TLS
  function caddySite() {
    return `# Aegis Relay: *${suffix} -> the Aegis at home, through the relay agent (written by it; don't edit)
*${suffix} {
	tls ${certFile} ${keyFile} {
		curves x25519mlkem768 x25519 secp256r1
	}
	header -Server
	reverse_proxy 127.0.0.1:${cfg.httpPort} {
		header_up X-Aegis-Client {remote_host}
	}
}
`;
  }
  function installCert(cert, privKey) {
    const x = new X509Certificate(cert);
    mkdirSync(cfg.certDir, { recursive: true });
    const write = (file, data, mode) => { writeFileSync(file + ".tmp", data, { mode }); renameSync(file + ".tmp", file); chmodSync(file, mode); };
    write(certFile, cert, 0o644);
    write(keyFile, privKey, 0o640);
    if (cfg.caddyGroup !== undefined) { try { chownSync(keyFile, 0, cfg.caddyGroup); } catch { /* not root: tests */ } }
    if (cfg.mode === "caddy") {
      const site = cfg.caddySite;
      if (cfg.replaces && existsSync(cfg.replaces)) { renameSync(cfg.replaces, cfg.replaces + ".before-aegis-relay"); log("moved aside", cfg.replaces); }
      if (!existsSync(site) || readFileSync(site, "utf8") !== caddySite()) { mkdirSync(dirname(site), { recursive: true }); writeFileSync(site, caddySite()); }
      if (cfg.reload !== false) execFile("systemctl", ["reload", "caddy"], (e) => log(e ? `caddy reload failed: ${e.message}` : "caddy reloaded with the new certificate"));
    } else loadCtx();
    log(`certificate for ${x.subjectAltName} until ${x.validTo}`);
    return { fingerprint: x.fingerprint256, notAfter: Date.parse(x.validTo) };
  }

  // the control side: only through the tunnel, only signed by your Aegis
  const control = httpServer((req, res) => {
    const reply = (status, obj) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (!verify(key, req.headers["x-aegis-relay"], { host: "agent", ip: "-", method: req.method, url: req.url })) return reply(401, { error: "not signed by your Aegis" });
    if (req.method === "GET" && req.url === "/status") {
      let cert = null;
      try { const x = new X509Certificate(readFileSync(certFile)); cert = { fingerprint: x.fingerprint256, notAfter: Date.parse(x.validTo), names: x.subjectAltName }; } catch { /* none yet */ }
      return reply(200, { version: VERSION, mode: cfg.mode, suffix, cert, stats });
    }
    if (req.method === "POST" && req.url === "/cert") {
      let body = "";
      req.on("data", (d) => { body += d; if (body.length > 64 * 1024) req.destroy(); });
      req.on("end", () => {
        try {
          const { cert, key: k } = JSON.parse(body);
          const x = new X509Certificate(cert);
          if (!x.subjectAltName.split(", ").some((n) => n === `DNS:*${suffix}`)) return reply(400, { error: `that certificate isn't for *${suffix}` });
          return reply(200, { ok: true, ...installCert(cert, k) });
        } catch (e) { return reply(400, { error: e.message }); }
      });
      return;
    }
    reply(404, { error: "not found" });
  });
  control.listen(cfg.controlPort, "127.0.0.1");
  return { front, control, stats, installCert, close: () => { front.close(); control.close(); } };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
  startAgent(cfg);
}
