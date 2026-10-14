// Your devices (aegis/devices.mjs): every browser that signed in, by its device key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Devices, deviceName } from "../aegis/devices.mjs";

test("names from the browser", () => {
  assert.equal(deviceName("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"), "Chrome on Windows");
  assert.equal(deviceName("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"), "Safari on iPhone");
  assert.equal(deviceName("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36"), "Chrome on Android phone");
  assert.equal(deviceName("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0"), "Edge on Mac");
  assert.equal(deviceName(""), "A browser");
});

test("a sign-in enrolls a device once; it keeps its id, its addresses and hosts; forget and rename", () => {
  const file = join(mkdtempSync(join(tmpdir(), "aegis-dev-")), "devices.json");
  const D = new Devices({ file });
  const ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/129.0 Safari/537.36";
  const id = D.enroll(null, { ip: "198.51.100.7", ua, host: "aegis.example.com" });
  assert.ok(D.has(id));
  assert.equal(D.enroll(id, { ip: "203.0.113.9", ua, host: "aegis.example.com" }), id, "the same browser signing in again");
  assert.notEqual(D.enroll("made-up-id", { ip: "203.0.113.9", ua }), "made-up-id", "an unknown id gets a fresh one");
  D.seen(id, { ip: "203.0.113.10", ua, host: "3000.tunnel.example.com" }, true);
  const me = D.list(id).find((d) => d.id === id);
  assert.equal(me.this, true);
  assert.equal(me.name, "Chrome on Windows");
  assert.deepEqual(me.ips.map((x) => x.ip).sort(), ["198.51.100.7", "203.0.113.10", "203.0.113.9"]);
  assert.deepEqual(me.hosts.map((x) => x.host).sort(), ["3000.tunnel.example.com", "aegis.example.com"]);
  assert.deepEqual(D.addresses()["203.0.113.10"].devices, [id]);
  D.rename(id, "  Alex's laptop  ");
  assert.equal(D.list().find((d) => d.id === id).name, "Alex's laptop");
  D.stop();
  const again = new Devices({ file });
  assert.ok(again.has(id), "kept across restarts");
  assert.ok(again.forget(id));
  assert.equal(again.has(id), false, "forgotten: its key is worth nothing now");
  again.forgetAll();
  assert.equal(again.list().length, 0);
  again.stop();
});
