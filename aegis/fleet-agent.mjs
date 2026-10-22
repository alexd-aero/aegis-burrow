// The way back in: a linked machine's agent keeps one WebSocket open to this
// dashboard, over the same HTTPS address a browser uses (a domain through
// Cloudflare, the VPS relay, a LAN address). When this gate can't reach the
// machine's SSH directly - another network, behind NAT, a firewall - it asks
// the agent for a stream, and the agent joins it to that machine's own SSH
// server on 127.0.0.1. SSH then runs through it as usual (ProxyCommand ->
// aegis/fleet-proxy.mjs -> a unix socket here), with the same key and the
// same host key check. Nothing is opened on either side.
//
//   control  GET /__gate/fleet/agent?id=&ts=&sig=           (Upgrade: websocket)
//            here -> agent: "open <n>"; agent -> here: "hello <json>", "ping"
//   stream   GET /__gate/fleet/agent/stream?id=&n=&ts=&sig=  binary both ways
//
// sig = HMAC-SHA256(machine.agentKey, "<id>|<ts>[|<n>]"), ts within 5 minutes.
// The agent only ever connects to its own machine's SSH port.

import { createHash, createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { chmodSync, rmSync } from "node:fs";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME = 1 << 20;
const OPEN_TIMEOUT = 15000;

export const sign = (key, ...parts) => createHmac("sha256", String(key)).update(parts.join("|")).digest("hex");
export const newAgentKey = () => randomBytes(24).toString("base64url");

// ---------------------------------------------------------------- frames
export function encode(data, opcode) {
  const body = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const op = opcode ?? (Buffer.isBuffer(data) ? 2 : 1);
  const len = body.length;
  const head = len < 126 ? Buffer.from([0x80 | op, len])
    : len < 65536 ? Buffer.from([0x80 | op, 126, len >> 8, len & 255])
    : (() => { const b = Buffer.alloc(10); b[0] = 0x80 | op; b[1] = 127; b.writeBigUInt64BE(BigInt(len), 2); return b; })();
  return Buffer.concat([head, body]);
}
// A WebSocket over a socket the HTTP server handed us. Frames from a client are masked.
export class Ws {
  constructor(socket, head) {
    this.socket = socket; this.buf = head?.length ? Buffer.from(head) : Buffer.alloc(0); this.frag = null;
    this.onmessage = null; this.onclose = null; this.closed = false;
    socket.setNoDelay(true);
    socket.on("data", (d) => { this.buf = Buffer.concat([this.buf, d]); this.read(); });
    socket.on("close", () => this.end());
    socket.on("error", () => this.end());
    if (this.buf.length) setImmediate(() => this.read());
  }
  read() {
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1], op = b0 & 15, masked = b1 & 128;
      let len = b1 & 127, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      if (len > MAX_FRAME) return this.close();
      const need = off + (masked ? 4 : 0) + len;
      if (this.buf.length < need) return;
      let body = this.buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const k = this.buf.subarray(off, off + 4); body = Buffer.from(body); for (let i = 0; i < body.length; i++) body[i] ^= k[i & 3]; }
      this.buf = this.buf.subarray(need);
      if (op === 8) return this.close();
      if (op === 9) { this.raw(encode(body, 10)); continue; }
      if (op === 10) continue;
      if (op === 0) { this.frag = Buffer.concat([this.frag || Buffer.alloc(0), body]); if (b0 & 128) { const all = this.frag; this.frag = null; this.onmessage?.(all, this.fragText); } continue; }
      if (!(b0 & 128)) { this.frag = Buffer.from(body); this.fragText = op === 1; continue; }
      this.onmessage?.(op === 1 ? body.toString("utf8") : Buffer.from(body), op === 1);
    }
  }
  raw(b) { if (!this.closed) { try { return this.socket.write(b); } catch { this.end(); } } return false; }
  send(data) { return this.raw(encode(data)); }
  close() { if (!this.closed) { try { this.socket.end(encode(Buffer.alloc(0), 8)); } catch { /* gone */ } } this.end(); }
  end() { if (this.closed) return; this.closed = true; try { this.socket.destroy(); } catch { /* gone */ } this.onclose?.(); }
}
export function accept(req, socket) {
  const key = req.headers["sec-websocket-key"];
  if (!key || String(req.headers.upgrade || "").toLowerCase() !== "websocket") return false;
  const acceptKey = createHash("sha1").update(key + GUID).digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey}\r\n\r\n`);
  return true;
}

// ---------------------------------------------------------------- the hub
export class AgentHub {
  // fleet: aegis/fleet.mjs Fleet; sock: the unix socket ProxyCommand dials
  constructor({ fleet, sock, log }) {
    Object.assign(this, { fleet, sock, log: log || console.log });
    this.agents = new Map();       // machine id -> {ws, since, info, lastPing}
    this.waiting = new Map();      // "<id>|<n>" -> resolve(ws)
    this.n = 0;
  }
  online(id) { const a = this.agents.get(id); return !!a && !a.ws.closed; }
  view(id) { const a = this.agents.get(id); return a && !a.ws.closed ? { since: a.since, lastPing: a.lastPing, version: a.info?.v || null } : null; }

  check(url, withN) {
    const id = url.searchParams.get("id") || "", ts = Number(url.searchParams.get("ts")) || 0, sig = url.searchParams.get("sig") || "";
    if (!/^m-[0-9a-f]{10}$/.test(id) || Math.abs(Date.now() / 1000 - ts) > 300 || !/^[0-9a-f]{64}$/.test(sig)) return null;
    let m; try { m = this.fleet.get(id); } catch { return { gone: true }; }        // forgotten here: its agent removes itself
    if (!m.agentKey) return null;
    const n = withN ? url.searchParams.get("n") || "" : null;
    const want = Buffer.from(sign(m.agentKey, id, ts, ...(withN ? [n] : [])), "hex");
    if (!timingSafeEqual(want, Buffer.from(sig, "hex"))) return null;
    return { m, n };
  }

  // The server's upgrade handler asks this first; true = it was ours.
  handleUpgrade(req, socket, head) {
    const url = new URL(req.url || "/", "http://x");
    if (url.pathname !== "/__gate/fleet/agent" && url.pathname !== "/__gate/fleet/agent/stream") return false;
    const stream = url.pathname.endsWith("/stream");
    const ok = this.check(url, stream);
    if (ok?.gone) { socket.end("HTTP/1.1 410 Gone\r\nConnection: close\r\n\r\n"); return true; }
    if (!ok) { socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"); return true; }
    if (!accept(req, socket)) { socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"); return true; }
    const ws = new Ws(socket, head);
    if (stream) {
      const k = `${ok.m.id}|${ok.n}`, w = this.waiting.get(k);
      if (!w) { ws.close(); return true; }
      this.waiting.delete(k);
      w(ws);
      return true;
    }
    const old = this.agents.get(ok.m.id);
    if (old) old.ws.close();
    const a = { ws, since: Date.now(), lastPing: Date.now(), info: null };
    this.agents.set(ok.m.id, a);
    this.log("fleet: agent connected for", ok.m.name);
    ws.onmessage = (msg, text) => {
      if (!text) return;
      a.lastPing = Date.now();
      if (msg.startsWith("hello ")) { try { a.info = JSON.parse(msg.slice(6)); } catch { /* fine */ } }
      else if (msg === "ping") ws.send("pong");
    };
    ws.onclose = () => { if (this.agents.get(ok.m.id) === a) { this.agents.delete(ok.m.id); this.log("fleet: agent gone for", ok.m.name); } };
    return true;
  }

  // A stream to that machine's SSH server, through its agent.
  open(id) {
    const a = this.agents.get(id);
    if (!a || a.ws.closed) return Promise.reject(new Error("its agent is not connected"));
    const n = String(++this.n);
    return new Promise((resolve, reject) => {
      const k = `${id}|${n}`;
      const t = setTimeout(() => { this.waiting.delete(k); reject(new Error("its agent did not open a stream in time")); }, OPEN_TIMEOUT);
      this.waiting.set(k, (ws) => { clearTimeout(t); resolve(ws); });
      a.ws.send(`open ${n}`);
    });
  }

  // ProxyCommand's side: a unix socket; the first line is the machine id.
  listen() {
    try { rmSync(this.sock, { force: true }); } catch { /* none */ }
    this.server = createServer((c) => {
      let head = Buffer.alloc(0), started = false;
      const onData = async (d) => {
        if (started) return;
        head = Buffer.concat([head, d]);
        const i = head.indexOf(10);
        if (i < 0) { if (head.length > 64) c.destroy(); return; }
        started = true; c.off("data", onData); c.pause();
        const id = head.subarray(0, i).toString().trim(), rest = head.subarray(i + 1);
        let ws;
        try { ws = await this.open(id); } catch (e) { c.end(`aegis: ${e.message}\n`); return; }
        if (rest.length) ws.send(rest);
        ws.onmessage = (m) => { if (!c.write(Buffer.isBuffer(m) ? m : Buffer.from(m))) { ws.socket.pause(); c.once("drain", () => ws.socket.resume()); } };
        ws.onclose = () => c.end();
        c.on("data", (x) => { if (ws.send(x) === false) { c.pause(); ws.socket.once("drain", () => c.resume()); } });
        c.on("close", () => ws.close());
        c.on("error", () => ws.close());
        c.resume();
      };
      c.on("data", onData);
      c.on("error", () => {});
    });
    this.server.listen(this.sock, () => { try { chmodSync(this.sock, 0o600); } catch { /* best effort */ } });
    this.server.on("error", (e) => this.log("fleet: agent socket:", e.message));
  }
  close() { this.server?.close(); for (const a of this.agents.values()) a.ws.close(); }
}
