// Tunnels with a name of their own (t.sub): naming, routing, and never taking
// over a DNS record that isn't Burrow's.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TunnelManager } from "../burrow/tunnels.mjs";

const DOMAIN = { mainHost: "aegis.example.com", tunnelId: "t-1", cert: "/nonexistent" };
function manager(records = {}) {
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "burrow-tun-")), domain: DOMAIN, quick: null, forbiddenPorts: [4310], log: () => {} });
  const dns = [];
  // Cloudflare, faked: GET finds `records`, POST/DELETE are noted
  tm.cfApi = async (method, path, body) => {
    dns.push(`${method} ${path}`);
    if (method === "GET") { const name = decodeURIComponent(/name=([^&]+)/.exec(path)[1]); return records[name] || []; }
    return { id: "r" + dns.length, ...body };
  };
  tm.detectScheme = async () => "http";
  tm.refreshFavicon = () => {}; tm.healthOne = () => {};
  return { tm, dns };
}

test("default and custom names", async () => {
  const { tm } = manager();
  try {
    await tm.create({ port: 3000 });
    assert.equal(tm.hostFor(3000), "tunnel-3000-aegis.example.com");
    assert.equal(tm.matchHost("tunnel-3000-aegis.example.com"), 3000);
    const t = await tm.update(3000, { sub: "Grafana" });
    assert.equal(t.sub, "grafana");
    assert.equal(t.url, "https://grafana.example.com");
    assert.equal(tm.matchHost("grafana.example.com"), 3000);
    assert.equal(tm.matchHost("tunnel-3000-aegis.example.com"), null, "the old name stops answering");
    await tm.update(3000, { sub: "" });
    assert.equal(tm.hostFor(3000), "tunnel-3000-aegis.example.com");
    assert.equal(tm.matchHost("grafana.example.com"), null);
    // a full name is fine too
    assert.equal((await tm.update(3000, { sub: "app.example.com" })).sub, "app");
  } finally { tm.stop(); }
});

test("names that are refused", async () => {
  const { tm } = manager({ "mail.example.com": [{ type: "MX", name: "mail.example.com", content: "x" }],
                           "www.example.com": [{ type: "CNAME", name: "www.example.com", content: "elsewhere.net" }],
                           "mine.example.com": [{ type: "CNAME", name: "mine.example.com", content: "t-1.cfargotunnel.com" }] });
  try {
    await tm.create({ port: 3000, sub: "one" });
    await tm.create({ port: 4000 });
    for (const bad of ["-x", "a_b", "aegis", "tunnel-5-x", "one", "mail", "www", "x".repeat(41)]) {
      await assert.rejects(tm.update(4000, { sub: bad }), Error, bad);
    }
    assert.equal((await tm.update(4000, { sub: "mine" })).sub, "mine", "a record that already points at our tunnel is ours");
    await assert.rejects(tm.create({ port: 5000, sub: "mine" }), /already uses/);
  } finally { tm.stop(); }
});
