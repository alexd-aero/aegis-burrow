import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanBlock, blockedBy, uploadWatch, dispositionName } from "../burrow/filetypes.mjs";
import { TunnelManager } from "../burrow/tunnels.mjs";

test("what people type", () => {
  assert.deepEqual(cleanBlock("GIF, .mp4  video/*"), { list: ["gif", "mp4", "video/*"], dir: "both" });
  assert.deepEqual(cleanBlock({ list: "gif", dir: "out" }), { list: ["gif"], dir: "out" });
  assert.equal(cleanBlock(""), null);
  assert.equal(cleanBlock({ list: "", dir: "in" }), null);
  assert.throws(() => cleanBlock("gif, <script>"), /isn't a file type/);
});
test("an extension blocks its types, a type blocks its extensions", () => {
  const r = cleanBlock("gif, video/*");
  assert.equal(blockedBy(r, { path: "/a/b.GIF?x=1" }), "gif");
  assert.equal(blockedBy(r, { path: "/image", type: "image/gif; charset=binary" }), "gif");
  assert.equal(blockedBy(r, { path: "/v", type: "video/mp4" }), "video/*");
  assert.equal(blockedBy(r, { path: "/clip.webm" }), "video/*");
  assert.equal(blockedBy(r, { path: "/page", type: "text/html" }), null);
  assert.equal(blockedBy(r, { name: "funny.gif" }), "gif");
  assert.equal(dispositionName(`attachment; filename*=UTF-8''cat%20pic.gif`), "cat pic.gif");
});
test("a form upload is watched part by part, even split across chunks", () => {
  const w = uploadWatch(cleanBlock("gif"));
  assert.equal(w(Buffer.from('--b\r\nContent-Disposition: form-data; name="t"\r\n\r\nhello\r\n--b\r\nContent-Disposition: form-data; name="f"; filena')), null);
  assert.equal(w(Buffer.from('me="x.gif"\r\nContent-Type: image/gif\r\n\r\nGIF89a')), "gif");
  const w2 = uploadWatch(cleanBlock("image/gif"));
  assert.equal(w2(Buffer.from('--b\r\nContent-Disposition: form-data; name="f"; filename="blob"\r\nContent-Type: image/gif\r\n\r\nGIF89a')), "image/gif");
});

test("through a tunnel: blocked out and in, everything else passes", async () => {
  let got = [];
  const app = createServer((req, res) => {
    let n = 0; req.on("data", (c) => { n += c.length; }); req.on("end", () => {
      got.push(`${req.method} ${req.url} ${n}`);
      if (req.url === "/cat.gif") { res.writeHead(200, { "Content-Type": "image/gif" }); return res.end("GIF89a"); }
      if (req.url === "/img") { res.writeHead(200, { "Content-Type": "image/gif" }); return res.end("GIF89a"); }
      res.writeHead(200, { "Content-Type": "text/html" }); res.end("<p>ok</p>");
    });
  });
  await new Promise((ok) => app.listen(0, "127.0.0.1", ok));
  const tm = new TunnelManager({ dataDir: mkdtempSync(join(tmpdir(), "burrow-ft-")), domain: null, quick: null, forbiddenPorts: [], log: () => {} });
  tm.detectScheme = async () => "http"; tm.refreshFavicon = () => {}; tm.healthOne = () => {}; tm.publish = async () => {};
  const port = app.address().port;
  await tm.create({ port, blockTypes: { list: "gif", dir: "both" } });
  const gate = createServer((req, res) => tm.proxy(port, req, res, { stripCookie: (c) => c }));
  await new Promise((ok) => gate.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${gate.address().port}`;
  try {
    assert.equal((await fetch(base + "/cat.gif")).status, 403);
    assert.equal((await fetch(base + "/img")).status, 403, "by its Content-Type");
    assert.equal(await (await fetch(base + "/page")).text(), "<p>ok</p>");
    const fd = new FormData(); fd.append("note", "hi"); fd.append("file", new Blob(["GIF89a"], { type: "image/gif" }), "x.gif");
    const up = await fetch(base + "/upload", { method: "POST", body: fd });
    assert.equal(up.status, 415);
    assert.ok(!got.some((g) => g.startsWith("POST /upload")), "the blocked upload never reached the app");
    const fd2 = new FormData(); fd2.append("file", new Blob(["PNG"], { type: "image/png" }), "x.png");
    assert.equal((await fetch(base + "/upload2", { method: "POST", body: fd2 })).status, 200);
    // only out: uploads pass
    await tm.update(port, { blockTypes: { list: "gif", dir: "out" } });
    const fd3 = new FormData(); fd3.append("file", new Blob(["GIF89a"], { type: "image/gif" }), "x.gif");
    assert.equal((await fetch(base + "/upload3", { method: "POST", body: fd3 })).status, 200);
    await tm.update(port, { blockTypes: "" });
    assert.equal((await fetch(base + "/cat.gif")).status, 200, "cleared");
  } finally { gate.close(); app.close(); tm.stop(); }
});
