// Updates: reading release commits, and the just-updated card.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.AEGIS_HOME = mkdtempSync(join(tmpdir(), "aegis-upd-"));
process.env.AEGIS_CONFIG_DIR = join(process.env.AEGIS_HOME, "config");
const { entry, Updater } = await import("../aegis/updater.mjs");
const { VERSION } = await import("../aegis/config.mjs");

test("a release commit", () => {
  const e = entry({ sha: "abcdef1234", html_url: "u", commit: { message: "2.4.0: updates by themselves\n\nMore words.\n\nCo-Authored-By: X <x@y>", committer: { date: "2026-10-06T00:00:00Z" } } });
  assert.deepEqual([e.version, e.title, e.short, e.body], ["2.4.0", "updates by themselves", "abcdef1", "More words."]);
  const plain = entry({ sha: "1", commit: { message: "burrow.py: point at Aegis" } });
  assert.equal(plain.version, null);
  assert.equal(plain.title, "burrow.py: point at Aegis");
});

test("auto-update and the just-updated card", () => {
  const store = {};
  const settings = { get: (k) => store[k], set: (p) => Object.assign(store, p) };
  const u = new Updater({ settings, log: () => {} });
  clearTimeout(u.timer);
  assert.equal(u.auto, false);
  u.setAuto(true);
  assert.equal(u.view().auto, true);
  store.updates.justUpdated = { from: "0.1.0", to: VERSION, at: Date.now() };
  assert.equal(u.view().justUpdated.from, "0.1.0");
  store.updates.justUpdated = { from: "0.1.0", to: "0.0.1", at: Date.now() };
  assert.equal(u.view().justUpdated, null, "only for the version that is running");
});
