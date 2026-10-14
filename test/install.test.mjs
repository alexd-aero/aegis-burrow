// The installer (bin/aegis install/upgrade) copies a fixed list of folders into
// app/: every folder the code imports from must be on it (2.16.0 shipped without
// relay/ and the gate didn't start).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

test("every folder the code imports from is copied by the installer", () => {
  const sh = readFileSync(new URL("../bin/aegis", import.meta.url), "utf8");
  const copied = new Set([...sh.matchAll(/"\$SRC_DIR\/([a-z]+)"/g)].map((m) => m[1]));
  for (const m of sh.matchAll(/for f in ([^;]+); do \[ -e "\$SRC_DIR\/\$f" \]/g)) for (const f of m[1].trim().split(/\s+/)) copied.add(f);
  const used = new Set();
  for (const dir of ["aegis", "burrow"]) {
    for (const f of readdirSync(new URL(`../${dir}/`, import.meta.url)).filter((n) => n.endsWith(".mjs"))) {
      const src = readFileSync(new URL(`../${dir}/${f}`, import.meta.url), "utf8");
      for (const m of src.matchAll(/from "\.\.\/([a-z]+)\//g)) used.add(m[1]);
    }
  }
  for (const d of used) assert.ok(copied.has(d), `${d}/ is imported but bin/aegis doesn't copy it`);
});
