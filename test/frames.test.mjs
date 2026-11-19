// Termix plugin frames (aegis/frames.mjs): their files pass, their own routes
// only with a key Termix minted for a page signed in here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FrameKeys, wsKeyOf, bearerOf } from "../aegis/frames.mjs";

const KEY = "eyJhbGciOiJIUzI1NiJ9.eyJwdXJwb3NlIjoicGx1Z2luLWZyYW1lIn0.sig-one";
const KEY2 = "eyJhbGciOiJIUzI1NiJ9.eyJwdXJwb3NlIjoicGx1Z2luLWZyYW1lIn0.sig-two";
const S = { sid: "s1", exp: Date.now() + 3600e3, e: null };
const req = (method, headers = {}) => ({ method, headers });

test("plugin files pass; nothing else without a key", () => {
  const f = new FrameKeys();
  assert.equal(f.allows(req("GET"), "/plugin-assets/_runtime/2a1d/assets/frame-x.js"), "asset");
  assert.equal(f.allows(req("HEAD"), "/plugin-assets/ssh-terminal/frontend.js"), "asset");
  assert.equal(f.allows(req("POST"), "/plugin-assets/ssh-terminal/frontend.js"), null);
  assert.equal(f.allows(req("GET"), "/plugin-assets/../users/me"), null);
  assert.equal(f.allows(req("GET"), "/plugin-api/ssh-terminal/x"), null);
  assert.equal(f.allows(req("GET", { authorization: `Bearer ${KEY}` }), "/plugin-api/ssh-terminal/x"), null, "a key nobody saw minted");
  assert.equal(f.allows(req("GET"), "/users/me"), null);
  assert.equal(f.allows(req("GET"), "/"), null);
});

test("a key minted for a signed-in page opens only its own plugin, until it runs out", () => {
  let now = 1_000_000;
  const f = new FrameKeys({ now: () => now });
  assert.equal(f.isTokenAsk("POST", "/plugins/frame-tokens"), true);
  assert.equal(f.isTokenAsk("POST", "/plugins/ssh-terminal/frame-token"), true);
  assert.equal(f.isTokenAsk("GET", "/plugins/frame-tokens"), false);
  assert.equal(f.learn("/plugins/frame-tokens", JSON.stringify({ tokens: { "ssh-terminal": { token: KEY, expiresIn: 300 }, "BAD id": { token: KEY2 } } }), S), 1);
  const auth = { authorization: `Bearer ${KEY}` };
  assert.equal(f.allows(req("GET", auth), "/plugin-api/ssh-terminal/hosts"), "key");
  assert.equal(f.allows(req("POST", auth), "/plugin-api/ssh-terminal"), "key");
  assert.equal(f.allows(req("GET", auth), "/plugin-api/docker/x"), null, "another plugin's routes");
  assert.equal(f.allows(req("GET", auth), "/users/me"), null, "core");
  // the WebSocket: the key rides in the subprotocol
  const ws = { "sec-websocket-protocol": `termix.jwt.${KEY}` };
  assert.equal(f.allows(req("GET", ws), "/plugin-ws/ssh-terminal/terminal", { ws: true }), "key");
  assert.equal(f.allows(req("GET", ws), "/plugin-ws/docker/console", { ws: true }), null);
  assert.equal(f.allows(req("GET"), "/plugin-ws/ssh-terminal/terminal", { ws: true }), null);
  // one plugin's own ask
  f.learn("/plugins/docker/frame-token", JSON.stringify({ token: KEY2, expiresIn: 300 }), S);
  assert.equal(f.allows(req("GET", { authorization: `Bearer ${KEY2}` }), "/plugin-api/docker/x"), "key");
  now += 331e3;
  assert.equal(f.allows(req("GET", auth), "/plugin-api/ssh-terminal/hosts"), null, "expired");
});

test("a key dies with the sign-in that asked for it; a silly lifetime is capped", () => {
  let now = 1_000_000, signedOut = false;
  const f = new FrameKeys({ now: () => now, alive: (s) => s?.sid === "s1" && !signedOut });
  f.learn("/plugins/frame-tokens", JSON.stringify({ tokens: { "ssh-terminal": { token: KEY, expiresIn: 1e9 } } }), S);
  const auth = { authorization: `Bearer ${KEY}` };
  assert.equal(f.allows(req("GET", auth), "/plugin-api/ssh-terminal/x"), "key");
  now += 16 * 60e3;
  assert.equal(f.allows(req("GET", auth), "/plugin-api/ssh-terminal/x"), null, "15 minutes at most");
  now = 1_000_000;
  f.learn("/plugins/frame-tokens", JSON.stringify({ tokens: { "ssh-terminal": { token: KEY, expiresIn: 300 } } }), S);
  signedOut = true;
  assert.equal(f.allows(req("GET", auth), "/plugin-api/ssh-terminal/x"), null, "signed out");
  assert.equal(f.learn("/plugins/frame-tokens", "not json", S), 0);
  assert.equal(f.learn("/users/me", JSON.stringify({ token: KEY }), S), 0);
});

test("only hashes are kept, and they survive a restart", async () => {
  const file = join(mkdtempSync(join(tmpdir(), "frames-")), "frame-keys.json");
  const f = new FrameKeys({ file });
  f.learn("/plugins/frame-tokens", JSON.stringify({ tokens: { "ssh-terminal": { token: KEY, expiresIn: 300 } } }), S);
  await new Promise((r) => setTimeout(r, 1200));
  const disk = readFileSync(file, "utf8");
  assert.ok(!disk.includes(KEY) && !disk.includes("sig-one"), "no key on disk");
  const g = new FrameKeys({ file });
  assert.equal(g.allows(req("GET", { authorization: `Bearer ${KEY}` }), "/plugin-api/ssh-terminal/x"), "key");
});

test("reading the key", () => {
  assert.equal(bearerOf(req("GET", { authorization: `Bearer ${KEY}` })), KEY);
  assert.equal(bearerOf(req("GET", { authorization: "Bearer short" })), null);
  assert.equal(wsKeyOf(req("GET", { "sec-websocket-protocol": `chat, termix.jwt.${KEY}` })), KEY);
  assert.equal(wsKeyOf(req("GET", { "sec-websocket-protocol": "termix.jwt." })), null);
});
