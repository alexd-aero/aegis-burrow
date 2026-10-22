// The way back in: a machine's agent dials the gate; the gate's SSH runs
// through it. Here a fake agent (Node's own WebSocket client) and an echo
// server standing in for sshd carry bytes both ways, signed per machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createServer as tcpServer, connect } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentHub, sign, newAgentKey } from "../aegis/fleet-agent.mjs";

const once = (em, ev) => new Promise((r) => em.once(ev, r));

test("a stream through the agent reaches SSH and back; a bad signature is refused", async () => {
  const key = newAgentKey(), id = "m-0123456789";
  const fleet = { get: (x) => { if (x !== id) throw new Error("no"); return { id, name: "box", agentKey: key }; } };
  const dir = mkdtempSync(join(tmpdir(), "agent-test-"));
  const hub = new AgentHub({ fleet, sock: join(dir, "a.sock"), log: () => {} });
  hub.listen();
  const http = createServer((q, s) => s.end("no"));
  http.on("upgrade", (req, socket, head) => { if (!hub.handleUpgrade(req, socket, head)) socket.destroy(); });
  http.listen(0, "127.0.0.1"); await once(http, "listening");
  const base = `ws://127.0.0.1:${http.address().port}`;
  const echo = tcpServer((c) => c.pipe(c)); echo.listen(0, "127.0.0.1"); await once(echo, "listening");

  const url = (path, n) => { const ts = Math.floor(Date.now() / 1000); return `${base}${path}?id=${id}&ts=${ts}&sig=${sign(key, id, ts, ...(n ? [n] : []))}${n ? `&n=${n}` : ""}`; };
  // a wrong key gets nowhere
  const bad = new WebSocket(`${base}/__gate/fleet/agent?id=${id}&ts=${Math.floor(Date.now() / 1000)}&sig=${"0".repeat(64)}`);
  await new Promise((r) => { bad.onerror = r; bad.onclose = r; });
  assert.equal(hub.online(id), false);

  // the agent: control link, and a stream per "open n" joined to "sshd"
  const ctl = new WebSocket(url("/__gate/fleet/agent"));
  ctl.binaryType = "arraybuffer";
  ctl.onmessage = (e) => {
    const m = String(e.data);
    if (!m.startsWith("open ")) return;
    const n = m.slice(5);
    const st = new WebSocket(url("/__gate/fleet/agent/stream", n));
    st.binaryType = "arraybuffer";
    const t = connect(echo.address().port, "127.0.0.1");
    st.onmessage = (ev) => t.write(Buffer.from(ev.data));
    t.on("data", (d) => st.send(d));
    st.onclose = () => t.destroy();
  };
  await new Promise((r) => { ctl.onopen = r; });
  ctl.send("hello {\"v\":\"1\"}");
  for (let i = 0; i < 50 && !hub.online(id); i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(hub.online(id), true);

  // ssh's side: the ProxyCommand socket; 200 kB both ways, big frames included
  const c = connect(join(dir, "a.sock"));
  await once(c, "connect");
  const payload = Buffer.alloc(200000, 7); payload.write("SSH-2.0-test", 0);
  c.write(`${id}\n`); c.write(payload);
  let got = Buffer.alloc(0);
  await new Promise((r) => c.on("data", (d) => { got = Buffer.concat([got, d]); if (got.length >= payload.length) r(); }));
  assert.equal(Buffer.compare(got.subarray(0, payload.length), payload), 0);
  c.destroy(); ctl.close(); hub.close(); http.close(); echo.close();
});

test("a machine whose agent isn't there says so instead of hanging", async () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-test-"));
  const hub = new AgentHub({ fleet: { get: () => ({}) }, sock: join(dir, "b.sock"), log: () => {} });
  hub.listen(); await new Promise((r) => setTimeout(r, 50));
  const c = connect(join(dir, "b.sock"));
  await once(c, "connect");
  c.write("m-aaaaaaaaaa\n");
  let said = "";
  await new Promise((r) => { c.on("data", (d) => { said += d; }); c.on("close", r); });
  assert.match(said, /agent is not connected/);
  hub.close();
});
