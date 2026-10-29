// Burrow, the engine: the relay doctor. Your tunnels through your VPS can look
// fine from here (every tunnel live, the link up) and still not reach anyone.
// This checks the way a visitor's request really takes, from the outside in,
// and fixes what it can by itself:
//
//   link    the SSH link to the VPS is up (else: brought up again; a forward
//           an old session still holds on the VPS is cleared, as root, when the
//           VPS is in Machines)
//   clock   both clocks against the web's time (Date headers of a few big
//           sites). Signatures only hold for a minute: a VPS whose clock drifted
//           turns every visitor away with "Not signed by your relay". This
//           machine signs in the VPS's time meanwhile (relaylink.mjs skew); the
//           agent switches NTP on, or sets its clock (agent 1.6+, else as root
//           over Machines). This machine's own clock is only reported: Aegis
//           has no root here.
//   cert    the VPS holds the certificate this machine has (else: pushed again)
//   path    per zone the VPS carries: HTTPS to the VPS's address, a random name
//           under that zone, /__aegis-relay/ping: Caddy (or the agent on 443),
//           the certificate, the agent, the link, the signature and this gate,
//           all in one; the answer must echo our nonce, MACed with a key only
//           this running gate has (a standby copy with the same data answers
//           too, and was once the whole outage)
//   dns     that name, at 1.1.1.1 and 8.8.8.8, points at the VPS
//   apps    each live tunnel's own port answers on this machine (a tunnel can
//           be "live" while the app behind it refuses connections)
//
// Each check is {id, ok, title, detail, fixed?, hint?}. A run is cheap and
// read-only unless something fails; fixes are only what Aegis did itself
// before (bring the link up, push certificates, update the agent) plus the
// clock and the stale forward. DNS records are only reported, never changed.

import { request as httpsRequest } from "node:https";
import { connect as netConnect, isIP } from "node:net";
import { Resolver } from "node:dns/promises";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";

const TIME_SOURCES = ["https://www.cloudflare.com/", "https://www.google.com/", "https://github.com/"];
const CLOCK_OK = 10e3;                         // a signature holds 60 s: more than 10 s off is worth fixing
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const secs = (ms) => `${Math.round(Math.abs(ms) / 1000)} s ${ms > 0 ? "ahead" : "behind"}`;

// The web's time: the median of what a few big sites' Date headers say, from
// this machine's clock (-> {offset: ours minus theirs, sources} or null).
export async function webClock(sources = TIME_SOURCES, { timeout = 6000 } = {}) {
  const one = (url) => new Promise((resolve) => {
    const t0 = Date.now();
    const r = httpsRequest(url, { method: "HEAD", timeout, headers: { "user-agent": "aegis-relay-doctor" } }, (res) => {
      res.resume();
      const t1 = Date.now(), d = Date.parse(res.headers.date || "");
      // a Date header has whole seconds: +500 is the middle of that second
      resolve(Number.isFinite(d) ? (t0 + t1) / 2 - (d + 500) : null);
    });
    r.on("timeout", () => r.destroy()); r.on("error", () => resolve(null));
    r.end();
  });
  const got = (await Promise.all(sources.map(one))).filter((x) => x !== null).sort((a, b) => a - b);
  if (!got.length) return null;
  return { offset: Math.round(got[Math.floor(got.length / 2)]), sources: got.length };
}

// HTTPS to the VPS's address with a name of ours: what does a visitor get?
// -> {kind, status?, code?, detail}
// gateId(nonce): this gate's answer for that nonce; another copy of it answers differently
export function probePath({ ip, port = 443, host, nonce, timeout = 15000, ca, gateId } = {}) {
  return new Promise((resolve) => {
    const r = httpsRequest({ host: ip, port, servername: host, method: "GET", path: `/__aegis-relay/ping?n=${nonce}`, timeout,
      headers: { host, "user-agent": "aegis-relay-doctor", accept: "application/json" }, ...(ca ? { ca } : {}) }, (res) => {
      let b = ""; res.setEncoding("utf8");
      res.on("data", (d) => { if (b.length < 4096) b += d; });
      res.on("end", () => {
        const mark = String(res.headers["x-aegis-relay"] || "");
        let j = null; try { j = JSON.parse(b); } catch { /* not ours */ }
        if (res.statusCode === 200 && mark === "ok" && j?.n === nonce) {
          if (!gateId || j.gate === gateId(nonce)) return resolve({ kind: "ok", status: 200, detail: "a visitor's request reaches this Aegis" });
          return resolve({ kind: "other-aegis", status: 200, standby: !!j.standby,
                           detail: j.standby ? "your standby copy (it took over once) holds the VPS link and gets the visitors, not this Aegis"
                                             : "another copy of this Aegis (same keys, another machine) holds the VPS link and gets the visitors" });
        }
        if (mark === "bad-signature" || /Not signed by your relay/.test(b)) return resolve({ kind: "bad-signature", status: res.statusCode, detail: "this Aegis turned the VPS's request away: its signature didn't check out" });
        if (mark === "home-offline" || /The home end isn.t connected/.test(b)) return resolve({ kind: "home-offline", status: res.statusCode, detail: "the VPS can't reach this machine: the link's forward isn't there on its side" });
        if (res.statusCode === 421) return resolve({ kind: "zone-missing", status: 421, detail: `the VPS doesn't carry ${host.replace(/^[^.]+/, "*")}` });
        if (/Access blocked/.test(b)) return resolve({ kind: "banned", status: res.statusCode, detail: "the VPS turns this machine's own address away (it's on the ban list)" });
        if (res.statusCode === 200 && mark === "ok") return resolve({ kind: "other-aegis", status: 200, detail: "an Aegis answered, but not with our nonce: another Aegis holds the link on that VPS" });
        resolve({ kind: "unexpected", status: res.statusCode, detail: `the VPS answered ${res.statusCode}${res.headers.server ? ` (${String(res.headers.server).slice(0, 40)})` : ""}${b ? `: ${b.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 140)}` : ""}` });
      });
    });
    r.on("timeout", () => r.destroy(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" })));
    r.on("error", (e) => {
      const c = e.code || "";
      if (/CERT|ALTNAME|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/.test(c)) return resolve({ kind: "cert", code: c, detail: `browsers would refuse its certificate (${c})` });
      if (c === "ECONNREFUSED") return resolve({ kind: "front-down", code: c, detail: "nothing answers on its port 443 (Caddy or the agent is down)" });
      if (c === "ETIMEDOUT" || c === "EHOSTUNREACH" || c === "ENETUNREACH") return resolve({ kind: "unreachable", code: c, detail: `its port 443 doesn't answer (${c}): a firewall, or the server is down` });
      if (c === "ECONNRESET" || /handshake|EPROTO/.test(c + e.message)) return resolve({ kind: "front-down", code: c || "EPROTO", detail: `the connection broke off at the start (${c || e.message})` });
      resolve({ kind: "unexpected", code: c, detail: e.message });
    });
    r.end();
  });
}

// Does something answer on this machine's port? (-> null, or why not)
export function portAnswers(port, host = "127.0.0.1", timeout = 3000) {
  return new Promise((resolve) => {
    const s = netConnect({ port, host, timeout });
    s.on("connect", () => { s.destroy(); resolve(null); });
    s.on("timeout", () => { s.destroy(); resolve("no answer"); });
    s.on("error", (e) => resolve(e.code === "ECONNREFUSED" ? "connection refused" : e.code || e.message));
  });
}

export class RelayDoctor {
  // link: a RelayLink. The rest are the gate's, so tests can stand in for them:
  //   wanted() -> do the tunnels go through the VPS?   bringUp() -> verifyRelay()
  //   zones() -> [".tunnel.example.com", …]            pushCerts({force}) -> push every certificate
  //   tunnels() -> [{port, host, targetHost, targetPort, name}] (live ones)
  //   root() -> null | {run(script) -> {code, out, err}} (the VPS in Machines, as root)
  //   updateAgent() -> relayUp()                         notify(n) / resolved(key)
  constructor({ link, dataDir, log, wanted, bringUp, zones, pushCerts, tunnels, root, updateAgent, notify, resolved, gateId, standbyBack,
                clock = webClock, probe = probePath, answers = portAnswers, dns, ca } = {}) {
    Object.assign(this, { link, log: log || console.log, wanted, bringUp, zones, pushCerts, tunnels: tunnels || (() => []), root: root || (() => null),
                          gateId, standbyBack: standbyBack || (() => null),
                          updateAgent: updateAgent || (async () => {}), notify: notify || (() => {}), resolved: resolved || (() => {}),
                          clock, probe, answers, ca });
    this.dns = dns || ((name) => this.lookup(name));
    this.file = dataDir ? join(dataDir, "relay", "doctor.json") : null;
    this.last = null; this.running = null; this.timer = null; this.fails = 0;
    try { if (this.file) this.last = JSON.parse(readFileSync(this.file, "utf8")); } catch { /* never ran */ }
  }
  save() {
    if (!this.file) return;
    try { writeFileSync(this.file + ".tmp", JSON.stringify(this.last)); renameSync(this.file + ".tmp", this.file); } catch { /* a nicety */ }
  }
  view() { return { last: this.last, running: !!this.running }; }

  // something looked off (a refused request, the link dropping): a run soon,
  // but not more than every two minutes
  soon(reason) {
    if (this.timer || this.running || !this.wanted?.()) return;
    const wait = Math.max(15e3, (this.last?.at || 0) + 120e3 - Date.now());
    this.timer = setTimeout(() => { this.timer = null; this.run({ reason }).catch((e) => this.log("relay doctor:", e.message)); }, wait);
    this.timer.unref?.();
  }
  // every few minutes while the tunnels use the VPS; every minute while it's broken
  start(every = 5 * 60e3) {
    const tick = () => {
      const wait = this.last && !this.last.ok ? 60e3 : every;
      this.loop = setTimeout(async () => { if (this.wanted?.()) await this.run({ reason: "scheduled" }).catch(() => {}); tick(); }, wait);
      this.loop.unref?.();
    };
    tick();
  }
  stop() { clearTimeout(this.loop); clearTimeout(this.timer); }

  async lookup(name) {
    const out = {};
    for (const server of ["1.1.1.1", "8.8.8.8"]) {
      const r = new Resolver({ timeout: 4000, tries: 2 }); r.setServers([server]);
      try { out[server] = await r.resolve4(name); } catch (e) { out[server] = e.code || e.message; }
    }
    return out;
  }

  run(opts = {}) {
    if (this.running) return this.running;
    this.running = this.diagnose(opts).finally(() => { this.running = null; });
    return this.running;
  }

  async diagnose({ fix = true, reason = "asked" } = {}) {
    const L = this.link, checks = [], started = Date.now();
    const add = (c) => { checks.push(c); return c; };
    const vps = L.state.vps?.host;
    if (!L.configured() || !vps) {
      return this.finish({ at: started, ok: false, reason, vps: null, checks: [add({ id: "link", ok: false, title: "No VPS is linked", detail: "Run the install command on your VPS (Settings → Domain → Your VPS)." })] }, fix);
    }
    if (!this.wanted()) {
      return this.finish({ at: started, ok: true, idle: true, reason, vps, checks: [add({ id: "link", ok: true, title: "Your VPS isn't carrying tunnels right now", detail: "Nothing goes through it, so there's nothing to check." })] }, fix);
    }

    // ---- the link
    let link = add({ id: "link", ok: L.link.state === "up", title: "The link to your VPS" });
    if (!link.ok && fix) {
      await this.bringUp();
      if (L.link.state !== "up" && /forwarding failed|port forwarding/i.test(L.link.error || L.checked?.error || "")) {
        if (await this.clearStaleForward()) { link.fixed = "cleared an old session that still held the forward on the VPS"; await this.bringUp(); }
      }
      link.ok = L.link.state === "up";
      if (link.ok) link.fixed ||= "brought the link up again";
    }
    link.detail = link.ok ? `up since ${new Date(L.link.since).toISOString().slice(11, 16)} UTC · agent ${L.agent?.version || "?"}`
      : (L.checked?.error || L.link.error || `the link is ${L.link.state}`);
    if (!link.ok) link.hint = "Aegis keeps trying by itself. If it stays down: is the VPS on, and does its SSH (port 22) answer?";

    // ---- the clocks
    const clock = add({ id: "clock", ok: true, title: "The clocks" });
    if (link.ok) await L.control("GET", "/status").then((s) => { L.agent = { ...s, at: Date.now() }; }).catch(() => {});
    const web = await this.clock().catch(() => null);
    const skew = L.clock && Date.now() - L.clock.at < 10 * 60e3 ? L.clock.skew : null;
    const mine = web ? web.offset : null;                       // this machine minus the web
    const theirs = mine !== null && skew !== null ? skew + mine : null;     // the VPS minus the web
    const parts = [];
    if (mine !== null && Math.abs(mine) > CLOCK_OK) {
      clock.ok = false;
      parts.push(`this machine's clock is ${secs(mine)}`);
      clock.hint = "Set this machine's clock right: sudo timedatectl set-ntp true (Aegis has no root here). The VPS link signs in the VPS's time meanwhile.";
    }
    if (theirs !== null && Math.abs(theirs) > CLOCK_OK) {
      parts.push(`the VPS's clock is ${secs(theirs)}`);
      if (fix) {
        const r = await this.fixVpsClock(mine).catch((e) => ({ error: e.message }));
        if (r?.ok) { clock.fixed = `set the VPS's clock right (${r.how})`; }
        else { clock.ok = false; clock.hint = `Set the VPS's clock right: timedatectl set-ntp true, as root there. ${r?.error ? `(Aegis couldn't: ${r.error})` : ""}`.trim(); }
      } else clock.ok = false;
    } else if (skew !== null && Math.abs(skew) > CLOCK_OK && mine === null) {
      clock.ok = false; parts.push(`the two clocks are ${Math.round(Math.abs(skew) / 1000)} s apart (the web's time couldn't be read to tell which is wrong)`);
    }
    clock.detail = parts.length ? parts.join("; ") : skew === null && mine === null ? "couldn't read either clock" : `in step${skew !== null ? ` (the VPS is ${Math.abs(skew) < 1000 ? "within a second" : secs(skew)} of this machine)` : ""}`;
    if (skew !== null && Math.abs(skew) > 5000 && !clock.fixed) clock.detail += "; signing in the VPS's time meanwhile";

    // ---- the agent and its certificates
    if (link.ok && fix && L.outdated() === "update") {
      const was = L.agent?.version;
      await this.updateAgent().catch(() => {});
      if (L.agent?.version !== was) add({ id: "agent", ok: true, title: "The agent on your VPS", detail: `${L.agent.version}`, fixed: `updated it from ${was}` });
    }

    // ---- the way in, per zone
    const zones = (this.zones() || []).filter(Boolean);
    let pushed = false, restarted = false, cleared = false;
    for (const zone of zones) {
      const c = add({ id: `path:${zone}`, ok: false, title: `Visitors at *${zone}` });
      let host = `aegis-check-${randomBytes(3).toString("hex")}${zone}`;
      let r = await this.probe({ ip: vps, host, nonce: randomBytes(9).toString("base64url"), ca: this.ca, gateId: this.gateId });
      if (r.kind !== "ok" && fix) {
        const before = r.kind;
        if ((r.kind === "cert" || r.kind === "zone-missing") && link.ok && !pushed) { pushed = true; await this.pushCerts({ force: true }).catch(() => {}); c.fixed = "pushed the certificates to the VPS again"; }
        else if (r.kind === "other-aegis" && !restarted) {
          // another copy of this gate answered (this one always signs its answer; an older copy
          // signs nothing): if it is our standby, a refresh from here makes it step aside
          const name = this.standbyBack();
          if (name) { c.fixed = `asked the standby on ${name} to step aside`; await sleep(this.standbyWait ?? 20000); }
          restarted = true; if (await this.clearStaleForward()) c.fixed = `${c.fixed ? c.fixed + "; " : ""}cleared its session on the VPS`;
          L.stop(); await this.bringUp(); c.fixed ||= "restarted the link";
        }
        else if (r.kind === "home-offline") {
          if (!cleared) { cleared = true; if (await this.clearStaleForward()) c.fixed = "cleared an old session that held the forward on the VPS"; }
          if (!restarted) { restarted = true; L.stop(); await this.bringUp(); c.fixed ||= "restarted the link"; }
        } else if (r.kind === "bad-signature" && !restarted) {
          // the clock was dealt with above; the link again, in case another session holds the forward
          restarted = true; await this.clearStaleForward(); L.stop(); await this.bringUp(); c.fixed = "restarted the link";
        } else if (r.kind === "front-down") {
          if (await this.restartFront()) c.fixed = "restarted the agent and Caddy on the VPS";
        }
        if (c.fixed) {
          await sleep(1500);
          host = `aegis-check-${randomBytes(3).toString("hex")}${zone}`;
          r = await this.probe({ ip: vps, host, nonce: randomBytes(9).toString("base64url"), ca: this.ca, gateId: this.gateId });
          if (r.kind !== "ok") c.fixed = `${c.fixed}, but that didn't help (was: ${before})`;
        }
      }
      c.ok = r.kind === "ok"; c.kind = r.kind; c.detail = r.detail;
      if (!c.ok) c.hint = HINTS[r.kind] || null;

      // the name, in public DNS
      const d = await this.dns(host).catch(() => null);
      if (d) {
        const res = Object.values(d), hits = res.filter((v) => Array.isArray(v) && v.includes(vps)).length;
        const wrong = res.find((v) => Array.isArray(v) && !v.includes(vps));
        const dc = add({ id: `dns:${zone}`, ok: hits > 0, title: `*${zone} in public DNS` });
        dc.detail = hits ? `points at ${vps}` : wrong ? `points at ${wrong.join(", ")}, not your VPS (${vps})` : `no record (${res.join(", ")})`;
        if (!hits) dc.hint = wrong && wrong.some((a) => /^(104\.|172\.6[4-9]|172\.7[01]\.|188\.114\.|162\.15[89]\.)/.test(a))
          ? `The *${zone} record is proxied by Cloudflare (orange cloud): it must be DNS only, pointing at ${vps}.`
          : `Point *${zone} (an A record, DNS only) at ${vps}.`;
      }
    }

    // ---- the apps behind the tunnels
    const down = [];
    for (const t of this.tunnels()) {
      const why = await this.answers(t.targetPort || t.port, t.targetHost || "127.0.0.1");
      if (why) down.push(`${t.name || t.host || t.port} (port ${t.targetPort || t.port}: ${why})`);
    }
    if (this.tunnels().length) add({ id: "apps", ok: !down.length, title: "The apps behind your tunnels", detail: down.length ? `not answering on this machine: ${down.join("; ")}` : "every live tunnel's port answers",
                                     ...(down.length ? { hint: "Start those apps (or pause their tunnels): a tunnel shows as live even while nothing answers behind it." } : {}) });

    const core = checks.filter((c) => c.id === "link" || c.id.startsWith("path:"));
    return this.finish({ at: started, took: Date.now() - started, reason, vps, ok: core.every((c) => c.ok), checks }, fix);
  }

  finish(report, fix) {
    const wasOk = this.last ? this.last.ok : true;
    this.last = report; this.save();
    const broken = report.checks.filter((c) => !c.ok), fixed = report.checks.filter((c) => c.fixed && c.ok);
    if (fixed.length) this.log(`relay doctor: fixed ${fixed.map((c) => `${c.title.toLowerCase()} (${c.fixed})`).join("; ")}`);
    if (!report.ok) {
      this.fails++;
      this.log(`relay doctor: ${broken.map((c) => `${c.title}: ${c.detail}`).join("; ")}`);
      // twice in a row, or at once when someone asked: the bell (and the banner)
      if (fix && (this.fails >= 2 || report.reason === "asked")) {
        const top = broken.find((c) => c.id.startsWith("path:")) || broken[0];
        this.notify({ level: "critical", key: "relay-doctor", title: "Your tunnels aren't reachable from the internet",
                      body: `${top.detail}.${top.hint ? ` ${top.hint}` : ""} Aegis checks again every minute and fixes what it can.`, link: "/__gate/settings#domain" });
      }
    } else {
      this.fails = 0;
      if (!wasOk && !report.idle) {
        this.resolved("relay-doctor");
        this.notify({ level: "info", key: "relay-doctor-ok", title: "Your tunnels are reachable again",
                      body: fixed.length ? `Fixed: ${fixed.map((c) => c.fixed).join("; ")}.` : "Visitors get through your VPS again." });
      }
    }
    return report;
  }

  // ---- fixes
  async fixVpsClock(mine) {
    const L = this.link, truth = () => Date.now() - (mine || 0);
    if (L.link.state === "up" && !L.can("clock") && L.outdated() === "update") await this.updateAgent().catch(() => {});
    if (L.link.state === "up" && L.can("clock")) {
      const r = await L.control("POST", "/clock", { truth: truth() }, 60000);
      await L.control("GET", "/status").catch(() => {});
      if (Math.abs(r.after) <= CLOCK_OK) return { ok: true, how: r.how.join(", ") || "ntp" };
      return { ok: false, error: `it is still ${secs(r.after)}` };
    }
    const root = this.root();
    if (!root) return { ok: false, error: L.link.state === "up" ? `the agent is ${L.agent?.version || "old"} and the VPS isn't in Machines` : "the link is down and the VPS isn't in Machines" };
    const r = await root.run(`${AS_ROOT}at=${Math.round(truth() / 1000)}; s0=$SECONDS
$S timedatectl set-ntp true 2>/dev/null; for s in systemd-timesyncd chrony chronyd ntp ntpd; do $S systemctl try-restart $s 2>/dev/null; done; sleep 5
want=$((at + SECONDS - s0)); d=$(( $(date +%s) - want ))
if [ \${d#-} -gt 3 ]; then $S date -u -s "@$want" >/dev/null || exit 1; $S hwclock --systohc 2>/dev/null; fi
echo ok`);
    return r.code === 0 ? { ok: true, how: "over Machines, as root" } : { ok: false, error: (r.err || r.out || "").trim().split("\n").pop() };
  }
  // an sshd session of aegis-relay that outlived its link still holds port 18452
  // on the VPS, so the new link's forward fails (or the old one gets the traffic)
  async clearStaleForward() {
    const root = this.root();
    if (!root) return false;
    const r = await root.run(`${AS_ROOT}$S pkill -u aegis-relay -x sshd 2>/dev/null; sleep 1; echo ok`).catch(() => null);
    return r?.code === 0;
  }
  async restartFront() {
    const root = this.root();
    if (!root) return false;
    const r = await root.run(`${AS_ROOT}$S systemctl restart aegis-relay-agent 2>/dev/null; if systemctl is-enabled -q caddy 2>/dev/null; then $S systemctl reload-or-restart caddy 2>/dev/null; fi; sleep 2; echo ok`).catch(() => null);
    return r?.code === 0;
  }
}

// Machines may know the VPS as root, or as a user with sudo (no password: -n)
const AS_ROOT = 'S=; [ "$(id -u)" = 0 ] || S="sudo -n"\n';

const HINTS = {
  "bad-signature": "The VPS's agent and this Aegis don't share the same key (or their clocks are far apart). If the clocks are right: Settings → Domain → Your VPS → Reinstall, and run the new command on the VPS.",
  "home-offline": "The VPS's agent can't reach this machine through the link. Aegis restarts the link by itself; if it stays like this, check that no other Aegis uses the same VPS.",
  "other-aegis": "Another copy of this Aegis (a standby that took over, an old install, or a restored backup) holds the VPS link and gets the visitors. Stop it there; Aegis 2.37.1+ standbys step aside by themselves once this machine is back.",
  "zone-missing": "The VPS doesn't have this zone's certificate yet: it's pushed when the link is up.",
  "cert": "The VPS has an old or wrong certificate. Aegis pushes its own again when the link is up.",
  "front-down": "Nothing answers on the VPS's port 443. On the VPS: systemctl restart aegis-relay-agent caddy (or add the VPS to Machines so Aegis can).",
  "unreachable": "The VPS's port 443 doesn't answer from here: a firewall (ufw, the provider's), or the server is off.",
  "banned": "This machine's own address is banned on the VPS: unban it under Bulwark (or Shield).",
  "unexpected": null,
};
