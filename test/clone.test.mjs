// Cloning another Aegis × Burrow link: what can be cloned, the sealed password
// hand-off, and what a clone passes on to the original.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webcrypto } from "node:crypto";
import { ml_kem768_x25519 as xwing } from "../aegis/vendor/pq.mjs";
import { parseCloneUrl, inspectClone, sealFor, CLONE_HEADER } from "../burrow/clone.mjs";
import { TunnelManager, checkLock } from "../burrow/tunnels.mjs";

test("links that can be pasted", () => {
  assert.deepEqual(parseCloneUrl("radio.tunnel.example.com/some/page?x=1"), { host: "radio.tunnel.example.com", url: "https://radio.tunnel.example.com/" });
  assert.equal(parseCloneUrl("https://Radio.Example.com.").host, "radio.example.com");
  for (const bad of ["", "http://a.example.com", "https://u:p@a.example.com", "https://a.example.com:8443", "https://localhost", "https://nas.local", "ftp://a.b", "https://x"]) {
    assert.throws(() => parseCloneUrl(bad), Error, bad);
  }
});

const json = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body });

test("asking a link who may open it", async () => {
  const seen = [];
  const answers = [json(403, null), json(200, { burrow: 1, aegis: "2.30.0", access: "password", name: "Radio" })];
  const info = await inspectClone("radio.example.com", { pause: 1, fetchImpl: async (u) => { seen.push(u); return answers.shift(); } });
  assert.deepEqual(seen, ["https://radio.example.com/__gate/burrow", "https://radio.example.com/__gate/burrow"], "a shield's first-visit check is waited out");
  assert.equal(info.access, "password");
  assert.equal(info.clonable, true);
  assert.equal(info.name, "Radio");
  assert.equal((await inspectClone("a.example.com", { fetchImpl: async () => json(200, { burrow: 1, access: "login" }) })).clonable, false);
  await assert.rejects(inspectClone("a.example.com", { fetchImpl: async () => json(200, { hello: 1 }) }), /isn't an Aegis × Burrow link/);
  await assert.rejects(inspectClone("a.example.com", { fetchImpl: async () => json(404, { burrow: 1, error: "paused" }) }), /paused/);
  await assert.rejects(inspectClone("a.example.com", { fetchImpl: async () => { throw Object.assign(new Error("x"), { cause: { code: "ENOTFOUND" } }); } }), /ENOTFOUND/);
});

// the gate's unwrapSealed (aegis/server.mjs), to check the Node sealing against
async function unwrap(msg, secretKey) {
  const ss = xwing.decapsulate(new Uint8Array(Buffer.from(msg.ct, "base64url")), secretKey);
  const key = async (label) => webcrypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-384", salt: new TextEncoder().encode(msg.id), info: new TextEncoder().encode(label) },
    await webcrypto.subtle.importKey("raw", ss, "HKDF", false, ["deriveKey"]), { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const inner = Buffer.from(await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(msg.iv, "base64url"), additionalData: new TextEncoder().encode("outer|" + msg.id) },
    await key("aegis/v1/outer"), Buffer.from(msg.c, "base64url")));
  const plain = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: inner.subarray(0, 12), additionalData: new TextEncoder().encode("inner|" + msg.id) },
    await key("aegis/v1/inner"), inner.subarray(12));
  return JSON.parse(new TextDecoder().decode(plain));
}

test("the password goes sealed, the way the gate opens it", async () => {
  const { publicKey, secretKey } = xwing.keygen();
  const msg = await sealFor({ id: "c-1", pk: Buffer.from(publicKey).toString("base64url") }, { password: "hunter2 ü" });
  assert.ok(!JSON.stringify(msg).includes("hunter2"));
  assert.deepEqual(await unwrap(msg, secretKey), { password: "hunter2 ü" });
});

const DOMAIN = { mainHost: "aegis.example.com", tunnelId: "t-1", cert: "/nonexistent" };
function manager(link) {
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "burrow-clone-")), domain: DOMAIN, quick: null, forbiddenPorts: [4310], log: () => {} });
  tm.cfApi = async (method, path, body) => (method === "GET" ? [] : { id: "r1", ...body });
  tm.detectScheme = async () => "http";
  tm.refreshFavicon = () => {}; tm.healthOne = () => {};
  tm.dnsAnswers = async () => true;
  const keys = [];
  tm.cloneApi = {
    inspect: async (url) => ({ ...parseCloneUrl(url), name: "Radio", aegis: "2.30.0", ...link }),
    key: async (host, pw) => { keys.push([host, pw]); if (pw !== "right") throw new Error(`That isn't the password of ${host}.`); return "KEY-" + host; },
  };
  return { tm, keys };
}

test("a public link clones as public, unless asked otherwise", async () => {
  const { tm, keys } = manager({ access: "public" });
  try {
    const t = await tm.create({ clone: "https://radio.tunnel.friend.dev/", sub: "radio" });
    assert.equal(t.kind, "clone");
    assert.equal(t.access, "public");
    assert.ok(t.port > 65535);
    assert.equal(t.url, "https://radio.example.com");
    assert.equal(t.target, "https://radio.tunnel.friend.dev/");
    assert.equal(t.name, "Radio");
    assert.deepEqual(keys, [], "nothing to unlock");
    assert.equal(tm.get(t.port).clone.key, null);
    const t2 = await tm.create({ clone: "radio.tunnel.friend.dev", sub: "radio2", access: "login" });
    assert.equal(t2.access, "login");
    await assert.rejects(tm.create({ clone: "radio.tunnel.friend.dev" }), /address of its own/);
  } finally { tm.stop(); }
});

test("a password link: its password once, a key from then on, never public", async () => {
  const { tm, keys } = manager({ access: "password" });
  try {
    await assert.rejects(tm.create({ clone: "pw.friend.dev", sub: "pw" }), /type it/);
    await assert.rejects(tm.create({ clone: "pw.friend.dev", sub: "pw", sourcePassword: "wrong" }), /isn't the password/);
    await assert.rejects(tm.create({ clone: "pw.friend.dev", sub: "pw", sourcePassword: "right", access: "public" }), /can't be public/);
    const t = await tm.create({ clone: "pw.friend.dev", sub: "pw", sourcePassword: "right" });
    assert.equal(t.access, "password");
    assert.ok(checkLock(tm.get(t.port).lock, "right"), "the same password as the original, by default");
    assert.equal(tm.get(t.port).clone.key, "KEY-pw.friend.dev");
    assert.ok(!JSON.stringify(t).includes("KEY-"), "the key never leaves the gate");
    assert.ok(!JSON.stringify(tm.get(t.port)).includes("right"), "nor is the password kept");
    const own = await tm.create({ clone: "pw.friend.dev", sub: "pw2", sourcePassword: "right", password: "mine" });
    assert.ok(checkLock(tm.get(own.port).lock, "mine"));
    await assert.rejects(tm.update(t.port, { access: "public" }), /can't be public/);
    // the original's password changed: the clone was cut off, then given the new one
    tm.cloneLost(tm.get(t.port), "password");
    assert.equal(tm.summary(tm.get(t.port)).clone.lost.why, "password");
    await tm.update(t.port, { sourcePassword: "right" });
    assert.equal(tm.summary(tm.get(t.port)).clone.lost, null);
    assert.equal(keys.length, 4);
  } finally { tm.stop(); }
});

test("links behind a login, and our own, are not cloned", async () => {
  const { tm } = manager({ access: "login" });
  try {
    await assert.rejects(tm.create({ clone: "x.friend.dev", sub: "x" }), /owner's Aegis login/);
    tm.cloneApi.inspect = async (url) => ({ ...parseCloneUrl(url), access: "public" });
    await tm.create({ port: 3000, sub: "mine" });
    await assert.rejects(tm.create({ clone: "mine.example.com", sub: "again" }), /your own tunnels/);
  } finally { tm.stop(); }
});

test("what a clone passes on, and what comes back", async () => {
  const { tm } = manager({ access: "password" });
  try {
    const { port } = await tm.create({ clone: "pw.friend.dev", sub: "pw", sourcePassword: "right" });
    const t = tm.get(port);
    const h = tm.upstreamHeaders(t, { headers: { host: "pw.example.com", origin: "https://pw.example.com", referer: "https://pw.example.com/a?b",
      "x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "1.2.3.4", [CLONE_HEADER]: "visitor's own", cookie: "app=1" }, socket: {} });
    assert.equal(h.host, "pw.friend.dev");
    assert.equal(h.origin, "https://pw.friend.dev");
    assert.equal(h.referer, "https://pw.friend.dev/a?b");
    assert.equal(h[CLONE_HEADER], "KEY-pw.friend.dev");
    assert.equal(h["x-forwarded-for"], undefined);
    assert.equal(h["cf-connecting-ip"], undefined);
    assert.equal(tm.cloneLocation(t, "https://pw.friend.dev/next?x#y"), "/next?x#y");
    assert.equal(tm.cloneLocation(t, "https://elsewhere.dev/"), "https://elsewhere.dev/");
    assert.deepEqual(tm.cloneCookies(t, ["a=1; Path=/; Domain=pw.friend.dev; Secure", "b=2; domain=.friend.dev", "c=3; Domain=other.dev"]),
                     ["a=1; Path=/; Secure", "b=2", "c=3; Domain=other.dev"]);
    // an ordinary tunnel never passes a visitor's clone header on
    await tm.create({ port: 3000 });
    assert.equal(tm.upstreamHeaders(tm.get(3000), { headers: { host: "x", [CLONE_HEADER]: "k" }, socket: {} }, {})[CLONE_HEADER], undefined);
  } finally { tm.stop(); }
});
