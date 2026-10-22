// A gate that moved to another machine (fleet-ops.mjs moveGate) stands down:
// no tunnels, no domain connector, no relay, no addons - only this notice on
// its old address, so whoever lands here learns where it went. `aegis
// resume-here` (bin/aegis) takes the mark off and it starts as a gate again.

import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function page(moved) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>This gate moved</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#030304;color:#eceef0;font:15px/1.55 Inter,ui-sans-serif,system-ui,sans-serif;padding:16px}
main{max-width:520px;padding:28px;border:1px solid rgba(255,255,255,.11);border-radius:18px;background:#101113}
h1{margin:0 0 8px;font-size:22px}p{margin:0 0 12px;color:#8a8f97}b{color:#eceef0}code{font:13px ui-monospace,monospace;background:#08090a;padding:2px 6px;border-radius:6px;color:#eceef0}
</style></head><body><main><h1>This gate moved</h1>
<p>Aegis × Burrow now runs on <b>${esc(moved.to)}</b>${moved.at ? ` (since ${esc(new Date(moved.at).toISOString().slice(0, 16).replace("T", " "))} UTC)` : ""}. Its login, domain, tunnels and addons went with it.</p>
<p>This machine only shows this notice. To run the gate here again instead, run <code>aegis resume-here</code> on this machine.</p></main></body></html>`;
}

export function serveMoved({ moved, listen, tls, tlsOptions, log }) {
  const handler = (req, res) => {
    if ((req.url || "").startsWith("/__gate/health")) {
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(JSON.stringify({ ok: false, app: "aegis-burrow", moved: { to: moved.to, at: moved.at } }));
    }
    res.writeHead(410, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'" });
    res.end(page(moved));
  };
  const server = tls ? createHttpsServer(tlsOptions(), handler) : createHttpServer(handler);
  server.listen(listen.port, listen.host, () => log(`moved to ${moved.to}: standing down, only the notice on ${listen.host}:${listen.port}`));
  return server;
}
export { readFileSync };
