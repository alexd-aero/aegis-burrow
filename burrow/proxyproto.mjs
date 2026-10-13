// The PROXY protocol (v1 and v2, haproxy.org/download/2.9/doc/proxy-protocol.txt):
// the header a relay puts in front of a connection it passes on unopened, so
// we still know who the visitor is. Read it, then hand the socket on with the
// bytes that came after it put back.

const V2_SIG = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);

// -> {header: bytes used, src: "203.0.113.7" | null} once buf holds a whole header,
//    null while it needs more, or throws when it isn't one.
export function parseProxyHeader(buf) {
  if (buf.length < 12 && V2_SIG.subarray(0, buf.length).equals(buf)) return null;     // a v2 header, still arriving
  if (buf.length >= 12 && buf.subarray(0, 12).equals(V2_SIG)) {
    if (buf.length < 16) return null;
    const ver = buf[12] >> 4, cmd = buf[12] & 15, fam = buf[13] >> 4, len = buf.readUInt16BE(14);
    if (ver !== 2) throw new Error("PROXY v2: bad version");
    if (buf.length < 16 + len) return null;
    let src = null;
    if (cmd === 1 && fam === 1 && len >= 12) src = [...buf.subarray(16, 20)].join(".");
    else if (cmd === 1 && fam === 2 && len >= 36) {
      const b = buf.subarray(16, 32), parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(b.readUInt16BE(i).toString(16));
      src = parts.join(":");
    }
    return { header: 16 + len, src };
  }
  const probe = buf.subarray(0, Math.min(buf.length, 6)).toString("latin1");
  if (!"PROXY ".startsWith(probe)) throw new Error("not a PROXY header");
  const end = buf.indexOf("\r\n");
  if (end < 0) { if (buf.length > 107) throw new Error("PROXY v1: too long"); return null; }
  const f = buf.subarray(0, end).toString("latin1").split(" ");
  if (f[0] !== "PROXY" || !["TCP4", "TCP6", "UNKNOWN"].includes(f[1])) throw new Error("PROXY v1: bad header");
  return { header: end + 2, src: f[1] === "UNKNOWN" ? null : f[2] };
}

// Wait for the header on a fresh socket: resolves {src}, with the rest of the
// bytes put back for whoever reads next (the TLS server).
export function readProxyHeader(sock, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const done = (err, val) => {
      clearTimeout(timer);
      sock.removeListener("data", onData);
      sock.removeListener("error", onErr);
      sock.removeListener("end", onEnd);
      err ? reject(err) : resolve(val);
    };
    const onErr = (e) => done(e);
    const onEnd = () => done(new Error("closed before the PROXY header"));
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      let r;
      try { r = parseProxyHeader(buf); } catch (e) { return done(e); }
      if (!r) return;
      sock.pause();
      const rest = buf.subarray(r.header);
      if (rest.length) sock.unshift(rest);
      done(null, { src: r.src });
    };
    const timer = setTimeout(() => done(new Error("no PROXY header in time")), timeoutMs);
    sock.on("data", onData);
    sock.on("error", onErr);
    sock.on("end", onEnd);
  });
}
