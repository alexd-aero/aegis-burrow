// A second tunnel on a port that already has one (a mirror): its own address, name
// and access, the same target, under a hidden key above 65535.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TunnelManager } from "../burrow/tunnels.mjs";

function manager() {
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "mirror-test-")), domain: { mainHost: "dash.example.com", tunnelId: "t-1", cert: "/nonexistent" },
                                 quick: null, forbiddenPorts: [4301], log: () => {}, naming: { mode: "wildcard", prefix: "tunnel", certs: "worker" } });
  tm.naming = { ...tm.naming, certs: "self", route: "vps", relay: "192.0.2.1" };
  tm.cfApi = async (method, path, body) => (method === "GET" ? [] : { id: "r1", ...body });
  tm.ensureWildcard = async () => ({ id: "w", name: "*.tunnel.example.com", ready: true });
  tm.detectScheme = async () => "http"; tm.refreshFavicon = () => {}; tm.healthOne = () => {}; tm.dnsAnswers = async () => true;
  return tm;
}

test("a port that already has a tunnel gets a second address for it", async () => {
  const tm = manager();
  try {
    await tm.create({ port: 4610, sub: "ax", access: "login" });
    const m = await tm.create({ port: 4610, sub: "axx", access: "login", name: "AX mirror" });
    assert.ok(m.port > 65535, "a hidden key, not the port");
    assert.equal(m.targetPort, 4610);
    assert.equal(m.targetHost, "127.0.0.1");
    assert.equal(tm.matchHost("ax.tunnel.example.com"), 4610);
    assert.equal(tm.matchHost("axx.tunnel.example.com"), m.port);
    assert.equal(tm.get(4610).sub, "ax", "the original is untouched");

    await assert.rejects(tm.create({ port: 4610, access: "login" }), /Give this one its own address/);
    await assert.rejects(tm.create({ port: 4610, sub: "ax", access: "login" }), /already uses ax/);

    await tm.update(m.port, { access: "public" });
    assert.equal(tm.get(m.port).access, "public", "its own access");
    assert.equal(tm.get(4610).access, "login");

    await tm.remove(4610);
    assert.ok(tm.get(m.port), "the mirror doesn't go with the original");
    assert.equal(tm.matchHost("axx.tunnel.example.com"), m.port);
  } finally { tm.stop?.(); }
});

test("a mirror forwards where its twin does, unless told otherwise", async () => {
  const tm = manager();
  try {
    await tm.create({ port: 3000, sub: "app", targetHost: "10.0.0.5", targetPort: 8080, access: "login" });
    const a = await tm.create({ port: 3000, sub: "app2", access: "login" });
    assert.equal(a.targetHost, "10.0.0.5"); assert.equal(a.targetPort, 8080);
    const b = await tm.create({ port: 3000, sub: "app3", targetPort: 9090, access: "login" });
    assert.equal(b.targetPort, 9090);
    assert.notEqual(a.port, b.port, "each its own key");
  } finally { tm.stop?.(); }
});
