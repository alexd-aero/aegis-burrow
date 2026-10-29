// Settings: link a domain through Cloudflare, Termix, the login, connected apps.
import { $, h, api, post, toast, ago, chrome, ICONS, UPD, updHero, verJump, runUpdate } from "./common.js";

const app = $("#app");
const S = { me: null, cf: null, termix: null, poll: null, busy: false,
            label: null,          // the dashboard name being typed (kept across repaints)
            renaming: false,      // the rename form for a linked domain is open
            upd: null, log: "aegis-burrow", logs: {}, logErr: {} };

const sec = (id, title, sub, body) => `<section class="card lit panel set" id="${id}">
  <div class="set-head"><h2>${title}</h2>${sub ? `<p>${sub}</p>` : ""}</div>${body}</section>`;

// ------------------------------------------------------------------ domain
// How tunnels are named: a DNS record each, or one wildcard *.<prefix>.<zone>,
// and where visitors arrive for it ("where"): your VPS (Aegis Relay), this
// machine (a port forward), a Cloudflare Worker, or Cloudflare's proxy.
const whereOf = (n) => !n?.active ? "vps" : n.certs === "self" ? (n.route === "vps" ? "vps" : "home") : n.certs && n.certs !== "auto" ? n.certs : "vps";
function namingDraft() {
  const n = S.naming || { mode: "record", prefix: "tunnel" };
  return { mode: S.nmDraft?.mode ?? n.mode, prefix: S.nmDraft?.prefix ?? (n.prefix ?? "tunnel"),
           relay: S.nmDraft?.relay ?? (n.relay || S.relay?.vps?.host || ""), where: S.nmDraft?.where ?? whereOf(n), accept: !!S.nmDraft?.accept };
}
// the draft as the API takes it
function namingBody(n) {
  const self = n.where === "vps" || n.where === "home";
  return { mode: n.mode, prefix: n.prefix, certs: self ? "self" : n.where, route: self ? n.where : undefined,
           relay: n.where === "vps" || n.where === "home" || n.where === "relay" ? n.relay : "", accept: n.accept };
}
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const day = (t) => new Date(t).toISOString().slice(0, 10);
const hm = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const certPill = (e) => e.issuing ? '<span class="pill warn"><i class="spin"></i> asking Let\'s Encrypt…</span>'
  : e.cert ? `<span class="pill ok"><i class="dot ok"></i>${h(e.cert.names[0] || "*." + e.base)} · Let's Encrypt${e.cert.staging ? " (staging)" : ""} · until ${h(day(e.cert.notAfter))}</span>`
  : `<span class="pill err"><i class="dot err"></i>no certificate${e.error ? ": " + h(e.error) : ""}</span>`;
// This machine's certificate and where the wildcard points right now.
function edgeStatus(e, zone) {
  if (!e) return "";
  if (e.route === "vps") {
    const route = e.relayPass ? `<span class="pill ok"><i class="dot ok"></i>through your VPS ${h(e.target)} · on this machine's certificate</span>`
      : `<span class="pill warn"><i class="dot warn"></i>your VPS ${h(e.target)} · not answering with this machine's certificate yet</span>`;
    return `<div class="kv-row"><span>Certificate</span>${certPill(e)}</div><div class="kv-row"><span>Route</span>${route}</div>`;
  }
  const route = e.via === "direct" && e.direct.ok ? `<span class="pill ok"><i class="dot ok"></i>straight to this machine · ${h(e.target)}</span>`
    : e.via === "relay" && e.relayPass ? `<span class="pill ok"><i class="dot ok"></i>through the backup VPS ${h(e.target)} · on this machine's certificate</span>`
    : e.via === "relay" ? `<span class="pill warn"><i class="dot warn"></i>through the backup relay · ${h(e.target)} · its own certificate</span>`
    : e.target ? `<span class="pill warn"><i class="dot warn"></i>this machine · ${h(e.target)} · not reachable yet</span>` : '<span class="pill">finding this machine\'s address…</span>';
  const fix = e.direct.ok ? ""
    : e.cgnat ? `<p class="note-err small"><b>Your internet provider shares one public address among many customers</b> (CGNAT: your router's outside address is <span class="mono">${h(e.cgnat.router)}</span>, the internet sees <span class="mono">${h(e.cgnat.internet || "another")}</span>). Nothing from outside can reach this machine, whatever the router allows. Use <b>Your VPS</b> or <b>Cloudflare Worker</b> above${e.relay ? ` (<span class="mono">${h(e.relay)}</span> serves the names meanwhile)` : ""}.</p>`
    : `<p class="faint small">${e.direct.why ? `Checked through ${h(e.publicIp || "the public address")}: ${h(e.direct.why)}. ` : ""}`
    + `Forward TCP port <b>443</b> on your router to <span class="mono">${h(e.lan || "this machine")}:${h(e.port)}</span>`
    + (e.upnp?.note ? ` (Aegis asked over UPnP; ${h(e.upnp.note)})` : "")
    + `. The record moves here by itself within two minutes of it working${e.relay ? `; until then <span class="mono">${h(e.relay)}</span> serves the names` : ""}.`
    + ` Opening a tunnel from your own home network can fail even when it works from outside (many routers don't loop back): check from your phone on mobile data.</p>`;
  return `<div class="kv-row"><span>Certificate</span>${certPill(e)}</div><div class="kv-row"><span>Route</span>${route}</div>${fix}`;
}

// ---- Your VPS: one pasted command links it (burrow/relaylink.mjs)
function vpsLinked(host) { const r = S.relay; return !!(r?.configured && r.vps?.host === host); }
// the install command shown has been run (the VPS registered after it was made)
const setupDone = (r) => !!(r?.setup && r.configured && r.vps?.host === r.setup.host && r.installed?.at > r.setup.created);
// the relay doctor's last run (burrow/relaydoctor.mjs): what a visitor really gets, and what it fixed
function doctorView() {
  const d = S.doctor;
  if (!d || d.idle) return "";
  const row = (c) => `<li class="small"><i class="dot ${c.ok ? "ok" : "err"}"></i> <b>${h(c.title)}</b> <span class="faint">· ${h(c.detail || "")}</span>
      ${c.fixed ? `<br><span class="small" style="color:var(--ok)">Fixed: ${h(c.fixed)}</span>` : ""}${!c.ok && c.hint ? `<br><span class="small">${h(c.hint)}</span>` : ""}</li>`;
  return `<div class="note-box${d.ok ? "" : " note-err"}" style="margin-top:12px">
      <p class="small"><b>${d.ok ? "Visitors get through" : "Visitors can't get through"}</b> <span class="faint">· checked from outside ${h(hm(d.at))}${d.reason && d.reason !== "asked" ? ` (${h(d.reason)})` : ""}</span></p>
      <ul style="margin:0;padding-left:0;list-style:none;display:grid;gap:6px">${d.checks.map(row).join("")}</ul></div>`;
}
function vpsPanel(n) {
  const r = S.relay || {}, host = n.relay, linked = vpsLinked(host);
  const setup = r.setup && r.setup.host === host && !setupDone(r) ? r.setup : null;
  const st = r.link?.state, chk = r.checked;
  let status = "";
  if (linked) {
    status = st === "up" ? `<span class="pill ok"><i class="dot ok"></i>linked · every request signed · agent ${h(r.agent?.version || "")}${r.agent?.cert ? ` · certificate until ${h(day(r.agent.cert.notAfter))}` : ""}</span>`
      : st === "connecting" || S.vpsChecking ? '<span class="pill warn"><i class="spin"></i> connecting to it…</span>'
      : chk && !chk.ok ? `<span class="pill err"><i class="dot err"></i>can't reach it</span>`
      : st === "down" ? `<span class="pill err"><i class="dot err"></i>link down</span>`
      : chk?.ok ? `<span class="pill ok"><i class="dot ok"></i>linked and checked ${h(hm(chk.at))} · idle until the tunnels move there</span>`
      : '<span class="pill"><i class="dot"></i>agent installed · not checked yet</span>';
  }
  const err = linked && st !== "up" && !S.vpsChecking ? (chk && !chk.ok ? chk.error : st === "down" ? r.link.error : null) : null;
  const step1 = `<label class="field" style="margin-top:12px"><span>Your VPS <span class="faint">(its public IPv4 address)</span></span>
      <div class="row vps-row"><input class="input mono" id="nmRelay" value="${h(host)}" maxlength="45" spellcheck="false" autocapitalize="none" placeholder="203.0.113.7">
      ${linked && !setup ? "" : `<button type="button" class="btn${setup ? "" : " primary"}" data-act="relay-setup" ${IPV4.test(host) ? "" : "disabled"}>${setup ? "New command" : "Get the install command"}</button>`}</div></label>`;
  const cmd = setup ? `<div class="vps-cmd">
      <p class="small"><b>Paste this in your VPS's terminal</b> (as root, or a user with sudo):</p>
      <div class="row vps-row"><input class="input mono" readonly value="${h(setup.command)}" id="vpsCmd"><button type="button" class="btn" data-act="relay-copy">Copy</button></div>
      <p class="faint small"><i class="spin"></i> Waiting for ${h(host)} to finish… This page notices by itself. The command works once, until ${h(hm(setup.expires))}.</p>
    </div>` : "";
  const state = linked ? `<div class="kv-row"><span>VPS</span>${status}</div>
      ${err ? `<p class="note-err small">${h(err)}</p>` : ""}
      <div class="row end" style="gap:8px;margin-top:8px"><button type="button" class="btn ghost sm" data-act="relay-forget">Forget it</button>
        <button type="button" class="btn ghost sm" data-act="relay-setup">Reinstall</button>
        <button type="button" class="btn ghost sm" data-act="relay-check" ${S.vpsChecking ? "disabled" : ""}>Check the link</button>
        <button type="button" class="btn sm" data-act="relay-doctor" ${S.doctorBusy ? "disabled" : ""}>${S.doctorBusy ? '<i class="spin"></i> Checking…' : "Check from outside and fix"}</button></div>
      ${doctorView()}` : "";
  return `${step1}${cmd}${state}
    <details class="adv" style="margin-top:10px"><summary>What the command does, and what the VPS needs</summary>
      <p class="faint small">Any Linux server with systemd, a public IPv4 address and root: port 443 free (or already served by Caddy, which it shares) and SSH on port 22. The command installs Node.js if needed, a small agent, and a user, <span class="mono">aegis-relay</span>, that only this Aegis's key can use, for two port forwards and nothing else. It opens 443 in ufw or firewalld if they block it, checks sshd allows the forward, and stops with the reason if anything is off. Then this Aegis connects to it over SSH (post-quantum where the server has it) to prove the link works.</p>
      <p class="faint small">Visitors arrive at the VPS, which holds a copy of this machine's certificate; every request it passes here is signed with a key only the two of them hold, so nothing else on that server can reach this Aegis. Your home address is never in DNS and nothing opens on your router.</p>
    </details>`;
}
// ---- This machine: the user forwards 443 themselves, knowing what it means
function homePanel(n, cur) {
  const e = cur.edge, wasHome = cur.active && cur.certs === "self" && cur.route === "home";
  const backup = vpsLinked(n.relay) || n.relay;
  return `<div class="note-box warn-box">
      <p><b>Not recommended.</b> Visitors connect straight to your home. You forward TCP port <b>443</b> on your router to <span class="mono">${h(e?.lan || "this machine")}:${h(e?.port || 18443)}</span> yourself; Aegis never changes your router.</p>
      <ul class="small">
        <li>Your home's public IP address goes into public DNS. Scanners that watch new certificates find it within minutes and probe it around the clock.</li>
        <li>Abuse lists, and some internet providers, can flag your home connection over that traffic.</li>
        <li>It can't work if your provider shares addresses (CGNAT), and from inside your own network it may fail even when it works outside.</li>
      </ul>
      ${wasHome ? "" : `<label class="check"><input type="checkbox" id="nmAccept" ${n.accept ? "checked" : ""}> I'll forward port 443 myself, and I accept the above</label>`}
    </div>
    <label class="field" style="margin-top:12px"><span>Backup VPS <span class="faint">(optional: its IP; it takes over while this machine can't be reached)</span></span>
      <input class="input mono" id="nmRelay" value="${h(n.relay)}" maxlength="45" spellcheck="false" autocapitalize="none" placeholder="none"></label>
    ${backup && !vpsLinked(n.relay) && n.relay ? `<p class="faint small">Link it under <b>Your VPS</b> first, so the backup carries the names signed and on this machine's certificate.</p>` : ""}`;
}
// ---- Cloudflare Worker: today's requests against the free plan's daily limit
function workerMeter(t) {
  if (!t) return "";
  const pct = Math.min(100, (t.n / t.limit) * 100), left = Math.max(0, t.reset - Date.now());
  const cls = pct >= 90 ? "err" : pct >= 70 ? "warn" : "ok";
  return `<div class="wk-meter" id="wkMeter">
      <div class="row" style="justify-content:space-between;align-items:baseline;gap:8px;flex-wrap:wrap">
        <span class="small"><span class="livedot"></span>Requests through the Worker today</span>
        <span class="mono"><b id="wkN">${t.n.toLocaleString()}</b> <span class="faint">/ ${t.limit.toLocaleString()}</span></span></div>
      <div class="bar ${cls}"><i id="wkBar" style="width:${pct.toFixed(2)}%"></i></div>
      <p class="faint small" id="wkReset">Resets at 00:00 UTC (in ${Math.floor(left / 3600e3)} h ${Math.floor((left % 3600e3) / 60e3)} min). Counted here as the Worker hands requests over; your other Workers on the same Cloudflare account count toward the same limit.</p>
    </div>`;
}
function startWorkerPoll() {
  clearInterval(S.wkPoll); S.wkPoll = null;
  if (!(S.naming?.active && S.naming.certs === "worker")) return;
  S.wkPoll = setInterval(async () => {
    if (document.hidden || !$("#wkMeter")) return;
    try {
      const j = await api("/__gate/api/tunnels/naming");
      const t = j.front?.today; if (!t) return;
      S.naming = j;
      $("#wkN").textContent = t.n.toLocaleString();
      const pct = Math.min(100, (t.n / t.limit) * 100), bar = $("#wkBar");
      bar.style.width = pct.toFixed(2) + "%";
      bar.parentElement.className = `bar ${pct >= 90 ? "err" : pct >= 70 ? "warn" : "ok"}`;
    } catch { /* next tick */ }
  }, 2500);
}
// ---- the relay's status when the tunnels went through an older hand-made relay (certs "relay")
function legacyRelayNote(n) {
  return `<label class="field" style="margin-top:12px"><span>Relay server (its IP)</span>
      <input class="input mono" id="nmRelay" value="${h(n.relay)}" maxlength="45" spellcheck="false" autocapitalize="none" placeholder="203.0.113.7"></label>
    <p class="faint small">An older setup: Caddy with on-demand TLS on a server of yours, set up by hand. <b>Your VPS</b> does the same with one pasted command, signed, on this machine's certificate.</p>`;
}
function namingSummary(d) {
  const n = S.naming;
  if (n?.active) return `<span class="mono">NAME.${h(n.prefix ? n.prefix + "." : "")}${h(d.zone)}</span> <span class="faint small">· one wildcard record, <span class="mono">${h(n.record)}</span>, serves them all</span>`;
  return `<span class="mono">tunnel-PORT-${h(d.mainHost)}</span> <span class="faint small">or a name of your own per tunnel · a DNS record each</span>`;
}
// The Worker front needs a Cloudflare credential that may edit Workers.
function frontForm(f) {
  if (S.frontLogin) return frontLoginPanel();
  if (f?.linked) return `<div class="kv-row"><span>Workers</span><span class="pill ok"><i class="dot ok"></i>connected${f.script ? ` · <span class="mono">${h(f.script)}</span>` : ""}</span></div>`;
  return `<p class="faint small" style="margin-top:10px">This needs one more yes from Cloudflare: permission to put up the Worker and its Custom Domains (Cloudflare's own login for its <span class="mono">wrangler</span> tool). The button below asks for it, then sets everything up.</p>
    <details class="adv"><summary>Or use an API token</summary>
      <label class="field" style="margin-top:10px"><span>Cloudflare API token <span class="faint">(Workers Scripts: Edit, Workers Routes: Edit)</span></span>
      <div class="row" style="gap:8px"><input class="input mono" id="frToken" type="password" autocomplete="off" spellcheck="false" placeholder="paste a token">
      <button type="button" class="btn" data-act="front-token">Connect</button></div></label>
      <p class="faint small">Make one under My Profile → API Tokens, from the "Edit Cloudflare Workers" template.</p></details>`;
}
// While Cloudflare's login is open in another tab.
function frontLoginPanel() {
  const l = S.frontLogin;
  if (l.status === "exchanging" || l.status === "setting-up") {
    return `<div class="kv-row"><span>Cloudflare</span><span class="pill warn"><i class="spin"></i> ${l.status === "exchanging" ? "connecting…" : "putting up the Worker and every tunnel name…"}</span></div>`;
  }
  return `<div class="note-box">
      <p><b>Allow it in the Cloudflare tab.</b> ${l.url ? `<a class="link" href="${h(l.url)}" target="_blank" rel="noopener">Open it again</a>` : ""}</p>
      <p class="faint small">When you click Allow, that tab goes to <span class="mono">localhost:8976</span>. If this browser runs on the machine Aegis runs on, that's all: it finishes by itself. Anywhere else, the tab shows a page that can't be reached. That's expected: copy its whole address and paste it here.</p>
      <div class="row" style="gap:8px"><input class="input mono" id="frPaste" autocomplete="off" spellcheck="false" placeholder="http://localhost:8976/oauth/callback?code=…">
      <button type="button" class="btn primary" data-act="front-finish">Finish</button><button type="button" class="btn ghost" data-act="front-cancel">Cancel</button></div>
      ${l.error ? `<div class="err-msg">${h(l.error)}</div>` : ""}
    </div>`;
}
// Start Cloudflare's login (naming: what to switch to once it's done), and follow it.
async function frontConnect(naming) {
  const tab = window.open("about:blank", "_blank");           // opened now, while the click still counts
  try {
    const j = await api("/__gate/api/tunnels/front/login", { method: "POST", body: JSON.stringify({ naming }) });
    S.frontLogin = { status: j.status, url: j.url, error: null };
    if (tab) tab.location.href = j.url; else window.open(j.url, "_blank");
  } catch (ex) { tab?.close(); S.nmErr = ex.message; S.frontLogin = null; }
  render();
  followFrontLogin();
}
async function followFrontLogin() {
  clearTimeout(S.frontPoll);
  if (!S.frontLogin) return;
  try {
    const j = await api("/__gate/api/tunnels/front/login");
    if (j.status === "done") { S.frontLogin = null; S.naming = j.naming; S.nmDraft = null; S.nmErr = ""; toast(`Cloudflare connected · tunnels live under ${j.naming.record || "their names"}`); render(); return; }
    if (j.status === "error" || j.status === "expired" || j.status === "none") {
      S.frontLogin = null; S.nmErr = j.status === "expired" ? "The Cloudflare login timed out; start again." : (j.error || "The Cloudflare login stopped."); render(); return;
    }
    const was = S.frontLogin.status;
    S.frontLogin = { ...S.frontLogin, status: j.status };
    if (was !== j.status) render();
  } catch { /* try again */ }
  S.frontPoll = setTimeout(followFrontLogin, 2000);
}
function namingHost(n, zone) { return `radio.${n.prefix ? n.prefix + "." : ""}${zone}`; }
const ROUTES = [
  { v: "vps", name: "Your VPS", tag: "Recommended", cls: "ok", sub: "Paste one command on a server of yours. Nothing opens at home." },
  { v: "home", name: "This machine", tag: "Not recommended", cls: "warn", sub: "You forward port 443 on your router. Your home IP goes public." },
  { v: "worker", name: "Cloudflare Worker", tag: "Free · 100k requests a day", cls: "", sub: "No server, nothing open at home. Cloudflare's daily limit applies." },
  { v: "cloudflare", name: "Cloudflare proxy", tag: "Paid certificate", cls: "", sub: "Cloudflare's edge; two-level names need Advanced Certificate Manager." },
];
function namingForm(d) {
  if (!S.naming) return "";
  const n = namingDraft(), cur = S.naming, w = n.where;
  const relayMatters = w === "vps" || w === "home" || w === "relay";
  const changed = n.mode !== cur.mode || (n.mode === "wildcard" && (n.prefix !== cur.prefix || w !== whereOf(cur) || !cur.active || (relayMatters && n.relay !== (cur.relay || ""))));
  const wild = `*.${n.prefix ? n.prefix + "." : ""}${d.zone}`;
  const help = {
    vps: `<span class="mono">${h(wild)}</span> points at your VPS. This machine keeps a free Let's Encrypt certificate for it (checked through your Cloudflare DNS, renewed by itself) and gives the VPS a copy; the VPS hands every request here over SSH, signed.`,
    home: `This machine gets a free Let's Encrypt certificate for <span class="mono">${h(wild)}</span> and serves the tunnels with it; <span class="mono">${h(wild)}</span> points straight at your home address.`,
    worker: `Each tunnel name becomes a Custom Domain of one small Cloudflare Worker, which comes with a free certificate for exactly that name, and the Worker hands requests here through this dashboard's Cloudflare tunnel. Nothing is opened at home and your address is never in DNS. A new name takes a few minutes to get its certificate.
      <br><b>Daily limit:</b> Cloudflare's free plan allows <b>100,000 Worker requests a day</b> for the whole account (all your Workers together). Past it, visitors get Cloudflare's error page until 00:00 UTC. A page with many images or a live app can use hundreds of requests per visit.`,
    relay: `<span class="mono">${h(wild)}</span> points at the relay. Caddy there fetches a free certificate for each tunnel name the first time it's opened, asking this gate first, and passes requests here over a reverse SSH tunnel. The relay sees the traffic.`,
    cloudflare: n.prefix ? `Through Cloudflare's proxy, which needs a certificate for <span class="mono">${h(wild)}</span> (Advanced Certificate Manager, paid); Aegis checks before it switches.` : `Through Cloudflare's proxy: its free certificate covers <span class="mono">${h(wild)}</span>. Names you already use on ${h(d.zone)} (mail, www…) keep their own records, which win over the wildcard.`,
  }[w];
  const routes = [...ROUTES, ...(w === "relay" || whereOf(cur) === "relay" ? [{ v: "relay", name: "Relay (older)", tag: "Set up by hand", cls: "", sub: "Caddy with on-demand TLS on a server of yours." }] : [])];
  const isCur = (v) => cur.active && whereOf(cur) === v;
  const blocked = w === "vps" && !vpsLinked(n.relay) ? "Link your VPS first: run the install command on it."
    : w === "home" && !(isCur("home")) && !n.accept ? "Confirm the port forward above first." : "";
  const saveLabel = n.mode === "wildcard" && w === "worker" && !cur.front?.linked ? "Connect Cloudflare &amp; move every tunnel"
    : n.mode === "wildcard" && w === "vps" ? "Move every tunnel to the VPS" : n.mode === "wildcard" && w === "home" ? "Move every tunnel to this machine" : "Move every tunnel";
  return `<div class="naming">
      <div class="row flexwrap" style="gap:12px;align-items:center">
        <b class="small">Tunnel addresses</b>
        <div class="seg" id="nmMode"><button type="button" data-v="record" class="${n.mode === "record" ? "on" : ""}">A DNS record per tunnel</button><button type="button" data-v="wildcard" class="${n.mode === "wildcard" ? "on" : ""}">One wildcard record</button></div>
      </div>
      ${n.mode === "wildcard" ? `<label class="field" style="margin-top:12px"><span>Wildcard</span>
          <div class="addr"><span class="mono zone">*.</span><input class="input mono" id="nmPrefix" value="${h(n.prefix)}" maxlength="60" spellcheck="false" autocapitalize="none" placeholder="(none)"><span class="mono zone">.${h(d.zone)}</span></div></label>
        <p class="faint small">Every tunnel is <span class="mono">NAME.${h(n.prefix ? n.prefix + "." : "")}${h(d.zone)}</span>: its own name, or its port (<span class="mono">${h(namingHost(n, d.zone))}</span>, <span class="mono">3000.${h(n.prefix ? n.prefix + "." : "")}${h(d.zone)}</span>). No DNS record is added per tunnel, so new tunnels answer at once.</p>
        <b class="small" style="display:block;margin-top:14px">Where visitors arrive</b>
        <div class="routes" id="nmCerts" role="radiogroup">${routes.map((r) => `<button type="button" role="radio" aria-checked="${w === r.v}" data-v="${r.v}" class="route${w === r.v ? " on" : ""}">
            <span class="route-top"><b>${r.name}</b>${isCur(r.v) ? '<span class="tag cur">in use</span>' : ""}</span>
            <span class="tag ${r.cls}">${r.tag}</span><small>${r.sub}</small></button>`).join("")}</div>
        <p class="faint small">${help}</p>
        ${cur.active && cur.certs === "self" && isCur(w) ? edgeStatus(cur.edge, d.zone) : ""}
        ${w === "vps" ? vpsPanel(n) : ""}
        ${w === "home" ? homePanel(n, cur) : ""}
        ${w === "worker" ? frontForm(cur.front) + (isCur("worker") ? workerMeter(cur.front?.today) : "") : ""}
        ${w === "relay" ? legacyRelayNote(n) : ""}`
      : `<p class="faint small" style="margin-top:10px">Each tunnel gets a DNS record of its own when it's made (<span class="mono">tunnel-3000-${h(d.mainHost)}</span>), so a brand-new name can take a minute to answer everywhere.</p>`}
      <div class="err-msg" id="nmErr">${h(S.nmErr || "")}</div>
      ${changed ? `<div class="row end" style="gap:8px;align-items:center">${blocked && n.mode === "wildcard" ? `<span class="faint small">${h(blocked)}</span>` : ""}<button type="button" class="btn ghost" data-act="naming-cancel">Cancel</button><button type="button" class="btn primary" data-act="naming-save" ${blocked && n.mode === "wildcard" ? "disabled" : ""}>${saveLabel}</button></div>` : ""}
    </div>`;
}

function domainBody() {
  const cf = S.cf;
  if (!cf) return '<p class="muted">Loading…</p>';
  if (cf.domain) {
    const d = cf.domain, c = cf.connector;
    return `<div class="linked">
        <div class="kv-row"><span>Dashboard</span><a class="mono" href="https://${h(d.mainHost)}" target="_blank" rel="noopener">https://${h(d.mainHost)}</a></div>
        <div class="kv-row"><span>Tunnels</span><span>${namingSummary(d)}</span></div>
        <div class="kv-row"><span>Connector</span>${!d.managed ? '<span class="pill">your own cloudflared service</span>'
          : c && c.running ? `<span class="pill ok"><i class="dot ok"></i>connected · post-quantum · since ${h(ago(c.since))}</span>` : '<span class="pill err"><i class="dot err"></i>not running</span>'}</div>
      </div>
      ${namingForm(d)}
      ${c && c.log && c.log.length ? `<details class="adv"><summary>Connector log</summary><pre class="log">${h(c.log.join("\n"))}</pre></details>` : ""}
      ${otherDomains(d)}
      ${S.renaming ? `<form id="renameForm" class="link-form" autocomplete="off">
          <label class="field"><span>New name for the dashboard</span>
            <div class="addr"><input class="input mono" id="label" value="${h(S.label ?? d.label)}" maxlength="40" spellcheck="false" autocapitalize="none"><span class="mono zone">.${h(d.zone)}</span></div></label>
          <div class="preview" id="labelPreview"></div>
          <p class="faint small">The old address stops working, so this page moves to the new one and you sign in there again. Tunnels named tunnel-PORT-… move with it; tunnels with a name of their own keep it.${d.managed ? "" : " Your own cloudflared service must already send the new name here (a *." + h(d.zone) + " rule in its ingress does); Aegis checks before it changes anything."}</p>
          <div class="err-msg" id="linkErr"></div>
          <div class="row end"><button type="button" class="btn ghost" data-act="rename-cancel">Cancel</button><button class="btn primary" id="linkGo">Rename</button></div>
        </form>`
      : d.managed ? `<div class="row end"><button class="btn" data-act="rename">Change the name</button><button class="btn danger" data-act="unlink">Unlink ${h(d.mainHost)}</button></div>`
        : `<p class="faint small">This address is routed by a cloudflared service Aegis did not create; Aegis manages the DNS records (the dashboard's, and ${S.naming?.active ? `the tunnels' one wildcard, <span class="mono">${h(S.naming.record)}</span>` : "one per tunnel"}).</p>
           <div class="row end"><button class="btn" data-act="rename">Change the name</button></div>`}`;
  }
  if (!cf.cloudflared) {
    return `<div class="note-err"><b>cloudflared is not installed.</b> Run <span class="mono">aegis doctor --fix</span> on this machine, or install it from
      <a class="link" href="https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/" target="_blank" rel="noopener">Cloudflare</a>, then reload.</div>`;
  }
  if (cf.cert) {
    const zone = cf.cert.zone && cf.cert.zone.name;
    return `<ol class="steps"><li class="done"><b>Cloudflare authorized</b><span>${zone ? `for <span class="mono">${h(zone)}</span>` : ""}</span></li><li class="on"><b>Pick the dashboard's name</b><span>Anything you like: aegis, home, private-termix…</span></li></ol>
      <form id="linkForm" class="link-form" autocomplete="off">
        <label class="field"><span>Name</span>
          <div class="addr"><input class="input mono" id="label" value="${h(S.label ?? "aegis")}" maxlength="40" spellcheck="false" autocapitalize="none" placeholder="aegis"><span class="mono zone">.${h(zone || "your-zone")}</span></div></label>
        <div class="preview" id="labelPreview"></div>
        <div class="err-msg" id="linkErr"></div>
        <div class="row end"><button type="button" class="btn ghost" data-act="forget">Use another account</button><button class="btn primary" id="linkGo">Link domain</button></div>
      </form>`;
  }
  const l = cf.login;
  if (l && (l.url || l.waiting)) {
    return `<ol class="steps"><li class="on"><b>Authorize Cloudflare</b><span>Open the link, sign in, pick the domain (zone) to use.</span></li><li><b>Pick the dashboard's name</b></li></ol>
      <div class="authbox">
        <a class="btn primary big" href="${h(l.url)}" target="_blank" rel="noopener">${ICONS.ext} Open the Cloudflare authorization</a>
        <p class="muted"><i class="spin"></i> Waiting for you to authorize… this page moves on by itself.</p>
        ${l.error ? `<p class="err-msg">${h(l.error)}</p>` : ""}
        <button class="btn ghost sm" data-act="cancel-login">Cancel</button>
      </div>`;
  }
  return `<p class="muted">Right now every tunnel gets a random <span class="mono">trycloudflare.com</span> name that changes when Aegis restarts.
      Link a domain on your Cloudflare account and the dashboard lives at a name you pick (<span class="mono">aegis.your-domain</span>, or any other), every tunnel at
      <span class="mono">tunnel-PORT-<i>name</i>.your-domain</span> or a subdomain of its own, through one post-quantum Cloudflare tunnel that Aegis runs for you.</p>
    ${l && l.error ? `<p class="err-msg">${h(l.error)}</p>` : ""}
    <div class="row end"><button class="btn primary" data-act="login">${ICONS.globe} Connect Cloudflare</button></div>`;
}

// ------------------------------------------------------------------ other domains
// More Cloudflare domains beside the main one (burrow/domains.mjs). Adding one:
// its name; access (whatever Aegis already holds is tried first; else a
// Cloudflare sign-in or an API token); then what answers there and, for the
// tunnels, the way in: your VPS (Aegis puts a certificate for *.<zone> on it,
// no command) or Cloudflare's proxy.
const OD_MODES = [["all", "All tunnels"], ["picked", "Picked ones"], ["none", "None"]];
const OD_ROUTES = [["vps", "Your VPS"], ["cloudflare", "Cloudflare"]];
const odSeg = (act, opts, cur, zone) => `<div class="seg od-seg" role="group">${opts.map(([v, t]) =>
  `<button type="button" data-act="${act}" data-v="${v}"${zone ? ` data-zone="${h(zone)}"` : ""} class="${cur === v ? "on" : ""}">${t}</button>`).join("")}</div>`;
const odHint = (m, zone) => m === "all" ? `Every tunnel at <span class="mono">NAME.${h(zone)}</span>: its own name, or its port.`
  : m === "picked" ? `Only tunnels you tick (the tunnel → Target → Other domains), at <span class="mono">NAME.${h(zone)}</span>.` : "Just the dashboard.";
const odRouteHint = (r, zone, vps, names) => r === "vps"
  ? `Straight to <span class="mono">${h(vps?.host || "your VPS")}</span>: Aegis gets a Let's Encrypt certificate for ${(names?.length ? names : [`*.${zone}`]).map((n) => `<span class="mono">${h(n)}</span>`).join(" and ")}, puts it on the VPS and renews it. Nothing to run there.`
  : "Through Cloudflare's proxy and a Cloudflare tunnel of this domain's own.";
function odVpsNote(o) {
  if (!o.vps) return '<p class="faint small">Link your VPS (Your VPS, above) and tunnels on other domains can go straight to it too.</p>';
  if (o.vps.outdated === "reinstall") return `<p class="note-warn small">The agent on ${h(o.vps.host)} is ${h(o.vps.version || "old")}. It needs one more run of the install command (Your VPS, above) to carry more domains; after that it updates itself.</p>`;
  return "";
}
function odRow(x, o) {
  const c = x.connector, ren = S.odRename === x.zone;
  const certLine = x.cert ? (x.cert.issuing ? '<span class="faint small"><i class="spin"></i> getting the certificate…</span>'
    : x.cert.error ? `<span class="err-msg small">certificate: ${h(x.cert.error)}</span>`
    : x.cert.notAfter ? `<span class="pill ok"><i class="dot ok"></i>certificate on ${h(o.vps?.host || "the VPS")} · until ${h(new Date(x.cert.notAfter).toLocaleDateString())}</span>` : "") : "";
  return `<div class="od-row" id="domain-${h(x.zone)}">
    <div class="od-top"><b class="mono">${h(x.zone)}</b>
      ${!c ? "" : c.running ? `<span class="pill ok"><i class="dot ok"></i>dashboard tunnel up · since ${h(ago(c.since))}</span>` : '<span class="pill err"><i class="dot err"></i>connector not running</span>'}
      <button class="btn ghost sm" data-act="od-remove" data-zone="${h(x.zone)}">Remove</button></div>
    <div class="kv-row"><span>Dashboard</span>${ren ? `<form class="od-ren" data-zone="${h(x.zone)}"><div class="addr"><input class="input mono sm" id="odRename" value="${h(x.label)}" maxlength="40" placeholder="none" spellcheck="false" autocapitalize="none"><span class="mono zone">.${h(x.zone)}</span></div><button class="btn sm primary">Save</button><button type="button" class="btn sm ghost" data-act="od-ren-cancel">Cancel</button></form>`
      : `${x.dashboard ? `<a class="mono" href="https://${h(x.dashboard)}" target="_blank" rel="noopener">https://${h(x.dashboard)}</a>` : '<span class="faint">none</span>'}<button class="btn ghost sm" data-act="od-ren" data-zone="${h(x.zone)}">${x.dashboard ? "Change" : "Add one"}</button>`}</div>
    <div class="kv-row"><span>Tunnels</span><span class="od-t">${odSeg("od-tunnels", OD_MODES, x.tunnels, x.zone)}<span class="faint small">${odHint(x.tunnels, x.zone)}</span></span></div>
    <div class="kv-row"><span>Subdomains</span>${odSubs(x, o)}</div>
    ${x.tunnels === "none" && !(x.subs || []).length ? "" : `<div class="kv-row"><span>Way in</span><span class="od-t">${odSeg("od-route", OD_ROUTES, x.route, x.zone)}<span class="faint small">${odRouteHint(x.route, x.zone, o.vps, x.cert?.names)}</span>${certLine}</span></div>`}
    ${c && c.log && c.log.length && !c.running ? `<details class="adv"><summary>Connector log</summary><pre class="log">${h(c.log.join("\n"))}</pre></details>` : ""}
  </div>`;
}
// A domain's subdomains (burrow/domains.mjs d.subs): a wildcard one carries the
// domain's tunnels one level further down (*.apps.<zone>, through your VPS); a
// single one is one tunnel's own name (blog.<zone>). Added and removed in place.
const tunName = (port) => { const t = (S.tuns || []).find((y) => y.port === port); return t ? t.name || t.title || t.sub || `port ${port}` : null; };
function odSubs(x, o) {
  const subs = x.subs || [], open = S.odSubOpen === x.zone, kind = S.odSubKind || "wild";
  const rows = subs.map((s) => {
    const name = s.wildcard ? null : tunName(s.port);
    return `<li class="od-sub ${s.wildcard ? "wild" : "one"}">
      <span class="od-sub-k" title="${s.wildcard ? "Wildcard" : "One tunnel"}">${s.wildcard ? "*" : ICONS.tunnel}</span>
      <span class="od-sub-two"><b class="mono">${h(s.host)}</b><span class="faint small">${s.wildcard
        ? `wildcard · ${x.tunnels === "picked" ? "the tunnels you pick" : "every tunnel"} at <span class="mono">${h(s.example)}</span>`
        : name ? `one tunnel · <b>${h(name)}</b> <span class="mono">:${h(s.port)}</span>` : `<span class="err-msg">its tunnel (${h(s.port)}) is gone</span>`}</span></span>
      <button type="button" class="btn ghost sm" data-act="od-sub-rm" data-zone="${h(x.zone)}" data-name="${h(s.name)}">Remove</button></li>`;
  }).join("");
  const opts = (S.tuns || []).filter((t) => t.kind !== "site" || t.port).map((t) => `<option value="${t.port}" ${String(S.odSubPort) === String(t.port) ? "selected" : ""}>${h(t.name || t.title || t.sub || "Tunnel")} · ${t.kind === "site" ? "site" : `:${t.port}`}</option>`).join("");
  const wildWhy = kind !== "wild" ? "" : x.route !== "vps" ? `A wildcard subdomain is two levels under ${h(x.zone)}: it needs the VPS way in (Cloudflare's free certificate covers one level).`
    : x.tunnels === "none" ? "A wildcard subdomain carries this domain's tunnels: set Tunnels to all or picked first." : "";
  const form = !open ? `<button type="button" class="btn ghost sm od-sub-open" data-act="od-sub-open" data-zone="${h(x.zone)}">+ Add a subdomain</button>`
    : `<form class="od-sub-add" data-zone="${h(x.zone)}" autocomplete="off">
        <div class="od-sub-line"><div class="addr"><span class="mono zone od-sub-star" ${kind === "wild" ? "" : "hidden"}>*.</span><input class="input mono sm" id="odSubName" value="${h(S.odSubName || "")}" maxlength="40" placeholder="${kind === "wild" ? "apps" : "blog"}" spellcheck="false" autocapitalize="none" aria-label="Subdomain"><span class="mono zone">.${h(x.zone)}</span></div>
          ${odSeg("od-sub-kind", [["wild", "Wildcard"], ["one", "One tunnel"]], kind, x.zone)}</div>
        ${kind === "one" ? (opts ? `<label class="od-sub-line"><span class="faint small">goes to</span><select class="input sm" id="odSubPort">${opts}</select></label>` : '<p class="faint small">No tunnels yet: add one on the Burrow page first.</p>') : ""}
        <p class="faint small">${kind === "wild" ? `Every tunnel ${x.tunnels === "picked" ? "you pick for this domain " : ""}also at <span class="mono">NAME.${h(S.odSubName || "apps")}.${h(x.zone)}</span>${x.route === "vps" ? "; Aegis gets its certificate and puts it on your VPS" : ""}.` : `Just that tunnel at <span class="mono">${h(S.odSubName || "blog")}.${h(x.zone)}</span>, a record of its own.`}</p>
        ${wildWhy ? `<p class="note-warn small">${wildWhy}</p>` : ""}
        <div class="err-msg small" id="odSubErr">${h(S.odSubErr || "")}</div>
        <div class="row"><button class="btn sm primary" ${wildWhy || (kind === "one" && !opts) ? "disabled" : ""}>Add</button><button type="button" class="btn sm ghost" data-act="od-sub-cancel">Cancel</button></div>
      </form>`;
  return `<span class="od-t">${subs.length ? `<ul class="od-subs">${rows}</ul>` : `<span class="faint small">None. Add a wildcard one (<span class="mono">*.apps.${h(x.zone)}</span>) or one tunnel's own (<span class="mono">blog.${h(x.zone)}</span>).</span>`}${form}</span>`;
}
const subsBody = (list) => list.map((s) => (s.wildcard ? { name: s.name, wildcard: true } : { name: s.name, wildcard: false, port: s.port }));
async function patchSubs(zone, subs, busyMsg) {
  S.busy = true;
  const at = document.getElementById(`domain-${zone}`)?.querySelector(".od-sub-add, .od-subs");
  at?.insertAdjacentHTML("afterend", `<span class="faint small od-sub-busy"><i class="spin"></i> ${busyMsg}</span>`);
  try { S.doms = await api(`/__gate/api/domains/${encodeURIComponent(zone)}`, { method: "PATCH", body: JSON.stringify({ subs }) }); return true; }
  finally { S.busy = false; document.querySelector(".od-sub-busy")?.remove(); }
}

function odAdd(o, main) {
  const l = o.login, p = o.pending, n = o.need;
  if (p) {
    const zone = p.zone || "the domain", mode = S.odMode || "all", route = S.odRoute || (o.vps ? "vps" : "cloudflare");
    return `<form id="odForm" class="od-add" autocomplete="off">
        <ol class="steps"><li class="done"><b>${h(zone)}</b><span>${p.via === "login" ? "authorized with Cloudflare" : `reached with ${h(p.via)} credentials`}</span></li><li class="on"><b>What answers there</b></li></ol>
        <label class="field"><span>The dashboard's name there <span class="faint">(empty: no dashboard)</span></span>
          <div class="addr"><input class="input mono" id="odLabel" value="${h(S.odLabel ?? "")}" maxlength="40" spellcheck="false" autocapitalize="none" placeholder="none"><span class="mono zone">.${h(zone)}</span></div></label>
        <div class="field"><span>Tunnels on it</span>${odSeg("od-mode", OD_MODES, mode)}<p class="faint small">${odHint(mode, zone)}</p></div>
        ${mode === "none" ? "" : `<div class="field"><span>Send them through your VPS?</span>${o.vps ? odSeg("od-route-new", [["vps", "Yes, set up a certificate on it"], ["cloudflare", "No, through Cloudflare"]], route) : ""}<p class="faint small">${o.vps ? odRouteHint(route, zone, o.vps) : "Through Cloudflare's proxy."}</p>${odVpsNote(o)}</div>`}
        <p class="faint small">Records already on ${h(zone)} (mail, www, a website) are never touched; a name with a record of its own keeps it. ${h(main.zone)} stays as it is.</p>
        <div class="err-msg" id="odErr">${h(S.odErr || "")}</div>
        <div class="row end"><button type="button" class="btn ghost" data-act="od-forget">Cancel</button><button class="btn primary" id="odGo">Add ${h(zone)}</button></div>
      </form>`;
  }
  if (l && (l.url || l.waiting)) {
    return `<div class="authbox">
        <a class="btn primary big" href="${h(l.url)}" target="_blank" rel="noopener">${ICONS.ext} Open the Cloudflare authorization</a>
        <p class="muted"><i class="spin"></i> Pick ${n ? `<b>${h(n.zone)}</b>` : "the other domain"} on Cloudflare's page… this moves on by itself.</p>
        ${l.error ? `<p class="err-msg">${h(l.error)}</p>` : ""}
        <button class="btn ghost sm" data-act="od-cancel">Cancel</button></div>`;
  }
  if (n) {
    return `<div class="od-add">
        <ol class="steps"><li class="on"><b>Access to ${h(n.zone)}</b><span>Aegis's Cloudflare access doesn't reach it yet.</span></li><li><b>What answers there</b></li></ol>
        <div class="od-auth">
          <div class="od-opt"><b>Sign in with Cloudflare</b><p class="faint small">Pick ${h(n.zone)} on Cloudflare's page. Works for everything, the dashboard included.</p>
            <button class="btn" data-act="od-login">${ICONS.globe} Sign in</button></div>
          <form class="od-opt" id="odTokenForm" autocomplete="off"><b>Or paste an API token</b>
            <p class="faint small">From <a class="link" href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener">your API tokens</a>: Zone → DNS → Edit. Give it <b>all zones</b> and every domain you add later needs nothing more. (A dashboard on the domain also needs Account → Cloudflare Tunnel → Edit.)</p>
            <input class="input mono sm" id="odToken" type="password" placeholder="Cloudflare API token" spellcheck="false" autocapitalize="none">
            <button class="btn">Use this token</button></form>
        </div>
        ${n.error || l?.error ? `<p class="err-msg">${h(n.error || l.error)}</p>` : ""}
        <div class="row end"><button type="button" class="btn ghost" data-act="od-forget">Cancel</button></div>
      </div>`;
  }
  return `<form id="odCheck" class="od-check" autocomplete="off">
      <input class="input mono" id="odZone" placeholder="another-domain.com" spellcheck="false" autocapitalize="none" value="${h(S.odZone || "")}">
      <button class="btn">${ICONS.globe} Add a domain</button>
    </form>${S.odErr ? `<p class="err-msg">${h(S.odErr)}</p>` : ""}`;
}
function otherDomains(main) {
  const o = S.doms;
  if (!o) return "";
  return `<div class="od">
    <div class="od-head"><h3>Other domains</h3><p class="faint small">More Cloudflare domains beside <span class="mono">${h(main.zone)}</span>: the dashboard and your tunnels answer on them too. Tunnels can go straight to your VPS, which gets a certificate for each domain by itself. One sign-in still covers every domain.</p></div>
    ${o.domains.map((x) => odRow(x, o)).join("")}
    ${odAdd(o, main)}
  </div>`;
}

// ------------------------------------------------------------------ updates
const PROJECTS = [
  { id: "aegis-burrow", name: "Aegis × Burrow", logo: "/__gate/logos/aegis-burrow.svg" },
  { id: "selkies-forge", name: "Selkies Forge", logo: "/__gate/logos/forge.svg" },
  { id: "weft", name: "Weft", logo: "/__gate/logos/weft.svg" },
  { id: "burrow-pages", name: "Burrow Pages", logo: "/__gate/logos/burrow-pages.svg" },
];
function updatesBody() {
  const u = S.upd;
  let hero;
  if (!u || S.checking) hero = updHero("checking", '<span class="uc-spin"></span>', "Checking for updates…", "Asking GitHub for the newest Aegis × Burrow.");
  else if (S.updPhase) hero = updHero("checking", '<span class="uc-spin"></span>', `Updating to v${h(u.latest)}…`, h(S.updPhase));
  else if (u.error && !u.latest) hero = updHero("bad", UPD.x, "Couldn't check", h(u.error))
    + `<div class="uc-foot"><span class="spacer"></span><button class="uc-btn" data-act="upd-check">Try again</button></div>`;
  else if (u.available) {
    const n = u.entries.length;
    hero = updHero("new", UPD.down, 'Update available <span class="new-chip">NEW</span>',
      `Version <span class="uc-pill">v${h(u.latest)}</span> is ready to install${n > 1 ? ` · ${n} changes` : ""}. Login, domain, tunnels and addons are kept.`, verJump(u.current, u.latest))
      + (n ? `<div class="uc-k">What's new</div><div class="uc-tl">${u.entries.map((e) => logItem(e, "new")).join("")}${logItem({ version: u.current, title: "the version you have", short: "" }, "cur")}</div>` : "")
      + `<div class="uc-foot"><span class="uc-when">Checked ${h(ago(u.checked))}</span><span class="spacer"></span><button class="uc-btn" data-act="upd-check">Check again</button>
         <button class="uc-go" data-act="upd-go">${UPD.down}<span>Update to v${h(u.latest)}</span></button></div>`;
  } else hero = updHero("ok", UPD.check, "You're up to date",
      `Aegis × Burrow <span class="uc-pill">v${h(u.current)}</span> is the newest version${u.justUpdated ? `, installed ${h(ago(u.justUpdated.at))} (from v${h(u.justUpdated.from)})` : ""}.`)
      + `<div class="uc-foot"><span class="uc-when">Checked ${h(ago(u.checked))}${u.error ? ` · ${h(u.error)}` : ""}</span><span class="spacer"></span><button class="uc-btn" data-act="upd-check">Check again</button></div>`;
  const auto = !!(u ? u.auto : S.me?.update?.auto);
  return `<div class="upcheck">${hero}</div>
    <div class="mod">
      <span class="mod-ico" aria-hidden="true">↻</span>
      <div class="grow"><b>Update by itself</b>
        <p class="muted small">Checks GitHub every 30 minutes (and whenever a page opens) and installs a new version as soon as it finds one. Aegis restarts for a few seconds; your login, domain, tunnels and addons are kept.
        ${u && u.scope === "manual" ? "<br><b>This copy runs under your own supervisor</b>: it installs, and the new version starts the next time that restarts it." : ""}</p></div>
      <label class="switch" title="${auto ? "On" : "Off"}"><input type="checkbox" id="autoUpd" ${auto ? "checked" : ""} aria-label="Update by itself"><i></i></label>
    </div>
    ${versionsBody()}`;
}
// Versions: the ones kept here (go back in a moment, no network), older releases
// from GitHub, and the one held back from auto-update
function versionsBody() {
  const v = S.vers;
  if (!v) return `<div class="vers"><div class="vers-h"><b>Versions</b><span class="faint small"><i class="spin"></i> loading…</span></div></div>`;
  if (v.error && !v.kept) return `<div class="vers"><div class="vers-h"><b>Versions</b><span class="err-msg small">${h(v.error)}</span></div></div>`;
  const b = v.boot, recentBack = b && b.state === "rolled-back" && Date.now() - b.at < 7 * 86400e3;
  const kept = (v.kept || []).filter((k) => !k.broken), broken = (v.kept || []).filter((k) => k.broken);
  const busy = S.versBusy;
  const row = (k, kind) => `<div class="vers-row ${kind}">
      <span class="vers-v mono">v${h(k.version)}</span>
      <span class="grow faint small">${kind === "cur" ? "running now" : kind === "broken" ? `didn't start · kept aside ${h(ago(k.at))}` : `kept ${h(ago(k.at))}${k.why ? ` · ${h(k.why)}` : ""}`}${v.hold?.version === k.version ? ' · <b class="vers-held">held back</b>' : ""}</span>
      ${kind === "kept" ? `<button class="uc-btn" data-act="ver-go" data-v="${h(k.version)}" ${busy ? "disabled" : ""}>${verNewer(k.version, v.current) ? "Switch" : "Go back"}</button>` : ""}
    </div>`;
  const rel = (v.releases || []).filter((r) => !r.kept).slice(0, 12);
  return `<div class="vers">
    <div class="vers-h"><b>Versions</b><span class="faint small">if an update misbehaves, go back; the version you leave is held back from auto-update</span></div>
    ${recentBack ? `<div class="vers-alert"><b>v${h(b.failed || b.from)} didn't start</b>, so Aegis went back to v${h(b.to)} by itself ${h(ago(b.at))}${b.why ? ` (it ${h(b.why)})` : ""}.</div>` : ""}
    ${v.hold ? `<div class="vers-hold"><span class="grow">v${h(v.hold.version)} is held back: auto-update waits for a version newer than it.</span><button class="uc-btn" data-act="ver-unhold">Allow it again</button></div>` : ""}
    ${busy ? `<div class="vers-busy"><span class="uc-spin"></span>${h(busy)}</div>` : ""}
    <div class="vers-list">${row({ version: v.current }, "cur")}${kept.map((k) => row(k, "kept")).join("")}${broken.map((k) => row(k, "broken")).join("")}</div>
    ${kept.length ? "" : '<p class="faint small" style="margin:6px 0 0">No earlier version is kept here yet: the one before is kept at each update from now on. Older releases can still come from GitHub, below.</p>'}
    ${rel.length ? `<details class="vers-more"><summary>Other releases on GitHub <span class="faint small">(the last ${rel.length})</span></summary>
      <div class="vers-list">${rel.map((r) => `<div class="vers-row"><span class="vers-v mono">v${h(r.version)}</span><span class="grow small" title="${h(r.title)}">${h(r.title)} <span class="faint">· ${h(r.date ? ago(r.date) : "")}</span></span>
        <button class="uc-btn" data-act="ver-go" data-v="${h(r.version)}" ${busy ? "disabled" : ""}>${r.newer ? "Install" : "Go back"}</button></div>`).join("")}</div></details>` : ""}
    <p class="faint small" style="margin:8px 0 0">With the gate down: <span class="mono">aegis rollback</span> in a terminal on this machine. A new version that doesn't start puts the one before back by itself.</p>
  </div>`;
}
const verNewer = (a, b) => { const x = String(a).split(".").map(Number), y = String(b).split(".").map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); return false; };
async function loadVersions() {
  try { S.vers = await api("/__gate/api/update/versions"); } catch (e) { S.vers = { error: e.message }; }
  render();
}
function logItem(e, kind) {
  const sha = e.short ? (e.url ? `<a href="${h(e.url)}" target="_blank" rel="noopener" title="See the commit"><span class="uc-sha">${h(e.short)}</span></a>` : `<span class="uc-sha">${h(e.short)}</span>`) : "";
  return `<div class="uc-item ${kind}"><span class="uc-node"></span>
    ${e.version ? `<span class="uc-tag ${kind === "new" ? "new" : ""}">v${h(e.version)}</span>` : ""}
    <div class="uc-msg"><b title="${h(e.title)}">${h(e.title || "(no message)")}</b><span>${h([e.date ? ago(e.date) : "", e.date ? new Date(e.date).toLocaleDateString() : ""].filter(Boolean).join(" · "))}</span></div>
    ${kind === "cur" ? '<span class="uc-tag">installed</span>' : sha}</div>`;
}
function changelogBody() {
  const id = S.log, L = S.logs[id], err = S.logErr[id];
  const p = PROJECTS.find((x) => x.id === id);
  const tabs = `<div class="seg cl-tabs" role="tablist">${PROJECTS.map((x) => `<button type="button" role="tab" data-act="log" data-id="${x.id}" class="${x.id === id ? "on" : ""}" aria-selected="${x.id === id}"><img src="${x.logo}" alt="">${h(x.name)}</button>`).join("")}</div>`;
  let body;
  if (err && !L) body = `<p class="err-msg">${h(err)}</p>`;
  else if (!L) body = '<p class="muted"><i class="spin"></i> Loading…</p>';
  else {
    let cur = id === "aegis-burrow" ? S.me?.version : id === "selkies-forge" ? (S.me?.integrations || []).find((i) => i.full)?.version : null;
    if (cur && !L.entries.some((e) => e.version === cur)) cur = null;
    // newer than what is installed here: green; the installed one: marked
    let seenCur = false;
    body = `<div class="uc-tl cl">${L.entries.map((e) => {
      const isCur = !!cur && e.version === cur && !seenCur;
      if (isCur) seenCur = true;
      return clItem(e, isCur ? "cur" : seenCur || !cur ? "" : "new");
    }).join("")}</div>
      <p class="faint small">From <a class="link" href="${h(L.repo)}/commits" target="_blank" rel="noopener">${h(L.repo.replace("https://", ""))}</a>${L.error ? ` · showing what was fetched earlier (${h(L.error)})` : ""}.</p>`;
  }
  return `${tabs}<div class="cl-head"><img src="${p.logo}" alt="" width="34" height="34"><div><b>${h(p.name)}</b><span class="faint small">${id === "weft" ? "the addon format both hosts share" : id === "selkies-forge" ? "desktops in the browser; an addon host" : "this gate and its tunnel engine"}</span></div></div>${body}`;
}
function clItem(e, kind) {
  const sha = e.url ? `<a href="${h(e.url)}" target="_blank" rel="noopener" title="See the commit"><span class="uc-sha">${h(e.short)}</span></a>` : `<span class="uc-sha">${h(e.short)}</span>`;
  return `<div class="uc-item ${kind}${e.version ? " rel" : ""}"><span class="uc-node"></span>
    ${e.version ? `<span class="uc-tag ${kind === "new" ? "new" : ""}">v${h(e.version)}</span>` : ""}
    <div class="uc-msg"><b title="${h(e.title)}">${h(e.title || "(no message)")}</b><span>${h(e.date ? `${new Date(e.date).toLocaleDateString()} · ${ago(e.date)}` : "")}</span>
    ${e.body ? `<details class="cl-more"><summary>details</summary><pre>${h(e.body)}</pre></details>` : ""}</div>
    ${kind === "cur" ? '<span class="uc-tag">installed</span>' : ""}${sha}</div>`;
}
function loadLog(id, force) {
  if (S.logs[id] && !force) return;
  api(`/__gate/api/changelog/${id}`).then((r) => { S.logs[id] = r; delete S.logErr[id]; render(); })
    .catch((e) => { S.logErr[id] = e.message; render(); });
}

// ------------------------------------------------------------------ advanced
// Where apps live: Termix at the dashboard's root (or Selkies Forge at its own
// address), or under a path of the dashboard, behind the same login.
const MOUNTS = [
  { id: "termix", name: "Termix", logo: "/__gate/logos/termix.svg", def: "/__gate/termix",
    root: () => `the root of ${S.me?.domain?.mainHost || "the dashboard's address"} (the home page stays at /, Termix opens from its tile)` },
  { id: "selkies-forge", name: "Selkies Forge", logo: "/__gate/logos/forge.svg", def: "/__gate/forge",
    root: () => { const f = (S.me?.integrations || []).find((i) => i.full); return `its own address${f?.local ? ` (${f.local.replace(/^https?:\/\//, "").replace(/\/$/, "")})` : ""}, or a Burrow tunnel`; } },
];
function advancedBody() {
  const me = S.me || {}, cur = me.mounts || {}, can = me.mountable || {};
  const rows = MOUNTS.filter((m) => can[m.id] || cur[m.id]).map((m) => {
    const on = S.mountDraft?.[m.id] !== undefined ? S.mountDraft[m.id] !== null : !!cur[m.id];
    const val = S.mountDraft?.[m.id] ?? cur[m.id] ?? m.def;
    const host = me.domain?.mainHost || location.host;
    return `<div class="mnt" data-mount="${m.id}">
      <img src="${m.logo}" alt="" width="36" height="36">
      <div class="grow"><b>${h(m.name)}</b>
        <div class="seg mnt-seg"><button type="button" data-mnt="root" class="${on ? "" : "on"}">At ${m.id === "termix" ? "the root" : "its own address"}</button><button type="button" data-mnt="path" class="${on ? "on" : ""}">Under a path</button></div>
        ${on ? `<div class="addr mnt-addr"><span class="mono zone">${h(host)}</span><input class="input mono" id="mnt-${m.id}" value="${h(val)}" maxlength="40" spellcheck="false" autocapitalize="none"></div>
          <p class="faint small">Behind the same login, at <span class="mono">${me.domain ? "https" : location.protocol.slice(0, -1)}://${h(host)}${h(val)}/</span>${m.id === "termix" ? ". The root then always shows the home page." : ". Its own address keeps working on this machine."}</p>`
        : `<p class="faint small">Now: ${h(m.root())}.</p>`}
      </div></div>`;
  }).join("");
  return `<details class="adv-set"${S.advOpen ? " open" : ""}><summary>Advanced <span class="faint small">· for people who know why they want it</span></summary>
    <div class="adv-in">
      <h3>Where apps live</h3>
      <p class="muted small">Serve an app under a path of the dashboard instead (like <span class="mono">/__gate/termix</span>), behind the same login. Burrow's tunnels always keep addresses of their own.</p>
      ${rows || '<p class="muted small">Nothing to move yet: Termix and Selkies Forge show up here once they are on this machine.</p>'}
      ${rows ? `<div class="err-msg" id="mntErr"></div><div class="row end"><button class="btn" id="mntGo">Save where apps live</button></div>` : ""}
    </div></details>`;
}

// ------------------------------------------------------------------ search all settings
// Every setting, by the words people use for it. Opens with the button, "/" or Ctrl+K.
const INDEX = [
  ["Name of this gate", "signin", "title name sign-in page brand"],
  ["Line under it on the sign-in page", "signin", "subtitle text login page"],
  ["Stay signed in for (days)", "signin", "session days cookie remember"],
  ["Lock out after wrong tries", "signin", "brute force attempts minutes lockout security"],
  ["Customize the home page", "signin", "dashboard tiles greeting tagline background columns gear links", "/?customize=1"],
  ["Check for updates", "updates", "update version upgrade new release"],
  ["Update by itself", "updates", "auto-update automatic updates"],
  ["Changelog: Aegis × Burrow", "changelog", "release notes what's new history versions", "log:aegis-burrow"],
  ["Changelog: Selkies Forge", "changelog", "release notes forge desktops", "log:selkies-forge"],
  ["Changelog: Weft", "changelog", "release notes addons format weft architecture", "log:weft"],
  ["Burrow on or off", "modules", "tunnels engine module switch"],
  ["Machine management", "modules", "machines fleet ssh link another machine remote host standby clone failover swap apps install graph", "/__gate/tunnels#/machines"],
  ["Serveo link", "modules", "public link serveousercontent phone url temporary"],
  ["Serveo link: send visitors on to the domain", "modules", "forward redirect serveo domain"],
  ["The full pack", "modules", "termix forge install welcome first run"],
  ["Domain", "domain", "cloudflare dns link custom domain address other domains more domains add a domain"],
  ["Change the dashboard's name (subdomain)", "domain", "rename subdomain name aegis private"],
  ["Subdomains on another domain: a wildcard one or one tunnel's", "domain", "subdomain subdomains wildcard more names apps blog other domains second level"],
  ["Unlink the domain", "domain", "remove cloudflare tunnel"],
  ["Termix", "termix", "ssh terminal install remove docker"],
  ["Change the username or password", "account", "login password user credentials"],
  ["Connected apps", "apps", "integrations selkies forge plugged in"],
  ["Burrow Pages: GitHub & GitLab Pages behind a password", "modules", "addon experimental github gitlab pages site secure reverse tunneling proxy custom domain subdomain password protect", "/__gate/tunnels#/pages"],
  ["Changelog: Burrow Pages", "changelog", "release notes pages addon", "log:burrow-pages"],
  ["A tunnel's own password (Burrow)", "account", "tunnel password own custom protect burrow share", "/__gate/tunnels"],
  ["Where apps live (an app under a path)", "advanced", "path mount subpath directory base url /__gate/termix /__gate/forge advanced root"],
];
function searchOpen() {
  if (document.querySelector(".srch")) return;
  const scrim = document.createElement("div");
  scrim.className = "scrim srch";
  scrim.innerHTML = `<div class="card lit srch-box" role="dialog" aria-label="Search all settings">
    <div class="srch-in"><span aria-hidden="true">${SEARCH}</span><input id="srchQ" class="input" placeholder="Search all settings" autocomplete="off" spellcheck="false"><kbd>esc</kbd></div>
    <div class="srch-list" id="srchList" role="listbox"></div></div>`;
  document.body.append(scrim);
  const q = scrim.querySelector("#srchQ"), list = scrim.querySelector("#srchList");
  let sel = 0, hits = [];
  const close = () => scrim.remove();
  const draw = () => {
    const words = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    hits = INDEX.filter(([t, s, k]) => words.every((w) => `${t} ${k} ${s}`.toLowerCase().includes(w)));
    // anything else on the page that says it
    if (words.length) {
      for (const el of document.querySelectorAll("section.set")) {
        const title = el.querySelector("h2")?.textContent || "";
        if (!hits.some((x) => x[1] === el.id) && words.every((w) => el.textContent.toLowerCase().includes(w))) hits.push([`“${q.value}” in ${title}`, el.id, ""]);
      }
    }
    sel = Math.min(sel, Math.max(0, hits.length - 1));
    list.innerHTML = hits.length ? hits.map(([t, s], i) => `<button type="button" class="srch-hit${i === sel ? " on" : ""}" data-i="${i}" role="option"><b>${h(t)}</b><span>${h(document.getElementById(s)?.querySelector("h2")?.textContent || "Advanced")}</span></button>`).join("")
      : '<p class="muted small srch-none">Nothing by that name. Try a word like domain, password, update, serveo.</p>';
  };
  const go = (i) => {
    const hit = hits[i];
    if (!hit) return;
    close();
    const [, s, , extra] = hit;
    if (extra && extra.startsWith("/")) { location.href = extra; return; }
    if (extra && extra.startsWith("log:")) { S.log = extra.slice(4); render(); loadLog(S.log); }
    if (s === "advanced") { S.advOpen = true; render(); }
    const el = s === "advanced" ? document.querySelector(".adv-set") : document.getElementById(s);
    if (!el) return;
    el.scrollIntoView({ block: "start", behavior: "smooth" });
    el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash");
  };
  q.addEventListener("input", () => { sel = 0; draw(); });
  q.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { sel = Math.min(sel + 1, hits.length - 1); draw(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
    else if (e.key === "Enter") go(sel);
    else if (e.key === "Escape") close();
  });
  list.addEventListener("click", (e) => { const b = e.target.closest(".srch-hit"); if (b) go(Number(b.dataset.i)); });
  scrim.addEventListener("mousedown", (e) => { if (e.target === scrim) close(); });
  draw();
  q.focus();
}
const SEARCH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>';
document.addEventListener("keydown", (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
  if ((e.key === "/" && !typing) || (e.key.toLowerCase() === "k" && (e.ctrlKey || e.metaKey))) { e.preventDefault(); searchOpen(); }
});

// ------------------------------------------------------------------ termix
function termixBody() {
  const t = S.termix;
  if (!t) return '<p class="muted">Loading…</p>';
  const logo = '<img class="set-logo" src="/__gate/logos/termix.svg" alt="" width="44" height="44">';
  if (t.configured) {
    return `<div class="row">${logo}<div class="grow"><b>Termix</b><div class="mono faint small">${h(t.upstream)}${t.container ? ` · container ${h(t.container)}` : ""}</div></div>
        ${t.up ? '<span class="pill ok"><i class="dot ok"></i>running</span>' : '<span class="pill err"><i class="dot err"></i>not answering</span>'}</div>
      <div class="row end"><a class="btn" href="/__gate/open/termix">${ICONS.ext} Open</a>${t.managed ? '<button class="btn danger" data-act="termix-remove">Remove</button>' : ""}</div>`;
  }
  const running = t.job && t.job.state === "running";
  return `<div class="row">${logo}<div class="grow"><b>Termix</b><div class="muted small">SSH terminals, a file manager and saved hosts, in the browser, behind this login. Aegis runs it in Docker, bound to 127.0.0.1.</div></div></div>
    ${t.job && t.job.lines.length ? `<pre class="log">${h(t.job.lines.join("\n"))}</pre>` : ""}
    ${!t.docker ? '<p class="err-msg">Docker is not available to Aegis on this machine.</p>' : ""}
    <div class="row end"><button class="btn primary" data-act="termix-install" ${running || !t.docker ? "disabled" : ""}>${running ? '<i class="spin"></i> Installing…' : "Install Termix"}</button></div>`;
}

// ------------------------------------------------------------------ account
function accountBody() {
  return `<form id="pwForm" autocomplete="off">
      <div class="row flexwrap">
        <label class="field grow"><span>Username</span><input class="input" id="pwUser" value="${h(S.me?.user || "")}" autocomplete="username" spellcheck="false" autocapitalize="none"></label>
        <label class="field grow"><span>Current password</span><input class="input" id="pwCur" type="password" autocomplete="current-password"></label>
      </div>
      <div class="row flexwrap">
        <label class="field grow"><span>New password <span class="faint">(10+ characters)</span></span><input class="input" id="pwNew" type="password" autocomplete="new-password"></label>
        <label class="field grow"><span>Repeat it</span><input class="input" id="pwNew2" type="password" autocomplete="new-password"></label>
      </div>
      <div class="err-msg" id="pwErr"></div>
      <div class="row end"><span class="faint small grow">Sealed with ML-KEM-768 + X25519 before it leaves this page. Every other browser is signed out.</span><button class="btn" id="pwGo">Change login</button></div>
    </form>`;
}

// ------------------------------------------------------------------ modules + sign-in
function modulesBody() {
  const on = !!S.me?.modules?.burrow;
  const sv = S.me?.serveo || {};
  const fl = S.me?.fleet || { enabled: false, machines: 0 };
  return `<div class="mod">
      <img src="/__gate/logos/burrow.svg" alt="" width="46" height="46">
      <div class="grow"><b>Burrow</b> <span class="pill">comes with Aegis</span>
        <p class="muted small">Tunnels: any port on its own HTTPS address, behind this login, with live traffic and clients. Switch it off if you only want the gate;
        your tunnels are kept, and they come back when you switch it on again.</p></div>
      <label class="switch" title="${on ? "On" : "Off"}"><input type="checkbox" id="modBurrow" ${on ? "checked" : ""} aria-label="Burrow on or off"><i></i></label>
    </div>
    <div class="mod">
      <span class="mod-ico" aria-hidden="true">⇄</span>
      <div class="grow"><b>Serveo link</b> ${sv.url ? `<span class="pill ok">up</span>` : sv.on ? `<span class="pill">connecting</span>` : ""}
        <p class="muted small">A public HTTPS address for this dashboard through serveo.net: no account, no domain. Handy for the first run or a phone.
        It goes through this gate like everything else: the sign-in page, then your password. Serveo gives it a new name each time Aegis restarts.</p>
        ${sv.url ? `<p class="mono small"><a class="link" href="${h(sv.url)}" target="_blank" rel="noopener">${h(sv.url)}</a></p>` : sv.on && sv.error ? `<p class="err-msg">${h(sv.error)}</p>` : ""}
        ${sv.on && S.me?.domain ? `<label class="row sub-switch"><span class="switch"><input type="checkbox" id="modServeoFwd" ${sv.forward !== false ? "checked" : ""}><i></i></span>
          <span class="small">Send its visitors on to <span class="mono">${h(S.me.domain.mainHost)}</span> <span class="faint">(off: the serveo link is a dashboard of its own, handy where the domain doesn't load, like on this machine's own network)</span></span></label>` : ""}</div>
      <label class="switch" title="${sv.on ? "On" : "Off"}"><input type="checkbox" id="modServeo" ${sv.on ? "checked" : ""} aria-label="Serveo link on or off"><i></i></label>
    </div>
    <div class="mod">
      <span class="mod-ico" aria-hidden="true"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg></span>
      <div class="grow"><b>Machine management</b> ${fl.machines ? `<span class="pill ok">${fl.machines} linked</span>` : '<span class="pill">new</span>'}
        <p class="muted small">Other machines you own, linked to this one with one command you run on them. Aegis makes itself one SSH key; from then on this
        dashboard draws them on a canvas, reads what they are made of and what runs on them, installs apps on them, moves an app and its data between two of
        them, and can keep a copy of this gate on one that takes over if this host goes down. Off until you switch it on, and nothing reaches out until a
        machine is linked.</p>
        ${fl.enabled ? `<p class="small"><a class="link" href="/__gate/tunnels#/machines">Open Machines</a>${fl.standby ? ` · ${fl.standby} standby` : ""}${fl.unreachable ? ` · <span class="err-msg">${fl.unreachable} unreachable</span>` : ""}</p>` : ""}</div>
      <label class="switch" title="${fl.enabled ? "On" : "Off"}"><input type="checkbox" id="modFleet" ${fl.enabled ? "checked" : ""} aria-label="Machine management on or off"><i></i></label>
    </div>
    <div class="mod">
      <img src="/__gate/logos/aegis-burrow.svg" alt="" width="46" height="46">
      <div class="grow"><b>The full pack</b>
        <p class="muted small">Selkies Forge, Termix (with its own login) and Burrow, set up in one go. ${S.me?.pack?.decided ? (S.me.pack.skipped ? "You skipped it." : "You set it up.") : ""}</p></div>
      <a class="btn sm" href="/__gate/welcome?again=1">Open the pack</a>
    </div>`;
}

function signinBody() {
  const me = S.me || {};
  return `<form id="siForm" autocomplete="off">
      <div class="row flexwrap">
        <label class="field grow"><span>Name of this gate</span><input class="input" id="siTitle" value="${h(me.title || "Aegis")}" maxlength="40"></label>
        <label class="field grow"><span>Line under it on the sign-in page</span><input class="input" id="siSub" value="${h(me.login?.subtitle || "Secure channel")}" maxlength="40"></label>
      </div>
      <div class="row flexwrap">
        <label class="field grow"><span>Stay signed in for <span class="faint">(days, 1-365)</span></span><input class="input" id="siDays" type="number" min="1" max="365" value="${h(me.sessionDays || 30)}"></label>
        <label class="field grow"><span>Lock out after <span class="faint">(wrong tries)</span></span><input class="input" id="siTries" type="number" min="3" max="50" value="${h(me.lockout?.attempts || 5)}"></label>
        <label class="field grow"><span>…for <span class="faint">(minutes)</span></span><input class="input" id="siMins" type="number" min="1" max="1440" value="${h(me.lockout?.minutes || 15)}"></label>
      </div>
      <div class="row end"><a class="btn ghost" href="/?customize=1">Customize the home page</a><span class="grow"></span><button class="btn" id="siGo">Save</button></div>
    </form>`;
}

function integrationsBody() {
  const list = S.me?.integrations || [];
  return `${list.length ? `<div class="ilist">${list.map((i) => `<div class="irow">
      <div class="integ-logo sm">${i.logo ? `<img src="${h(i.logo)}" alt="">` : h(i.name[0])}</div>
      <div class="grow"><b>${h(i.name)}</b> <span class="faint mono small">${h(i.version ? "v" + i.version : "")}</span><div class="faint small mono">${h(i.local || "")}</div></div>
      ${i.full ? `<a class="btn sm" href="/__gate/tunnels#/i/${h(i.id)}">Desktops</a>` : ""}
      <a class="btn sm ghost" href="${h(i.dashboard)}" target="_blank" rel="noopener">${ICONS.ext} Open</a></div>`).join("")}</div>`
    : '<p class="muted">Nothing has plugged in yet.</p>'}
    <p class="faint small">Apps plug in by dropping a JSON file into <span class="mono">~/.config/aegis/integrations/</span>. Selkies Forge does this by itself when it runs on this machine.</p>`;
}

function render() {
  if (S.busy) return;
  const me = S.me || {};
  const focusId = document.activeElement?.id;
  if (focusId && (["label", "odLabel", "odRename", "odZone", "odToken", "nmPrefix", "nmRelay", "pwUser", "pwCur", "pwNew", "pwNew2", "siTitle", "siSub", "siDays", "siTries", "siMins", "frPaste", "frToken", "odSubName"].includes(focusId) || focusId.startsWith("mnt-"))) return;   // never repaint under typing
  if (document.querySelector(".srch")) return;   // nor under the search box
  app.innerHTML = `
    <div class="head"><div><h1>Settings</h1><p>${h(me.title || "Aegis")} ${me.version ? `<span class="mono faint">v${h(me.version)}</span>` : ""}</p></div>
      <div class="spacer"></div><button class="btn srch-btn" data-act="search" title="Search all settings (/ or Ctrl+K)">${SEARCH}<span>Search all settings</span><kbd>/</kbd></button></div>
    ${sec("signin", "Sign-in", "What the sign-in page says, and how long a sign-in lasts.", signinBody())}
    ${sec("updates", "Updates", "New versions of Aegis × Burrow, by hand or by themselves.", updatesBody())}
    ${sec("changelog", "Changelog", "What changed lately in Aegis × Burrow, Selkies Forge and the Weft Architecture.", changelogBody())}
    ${sec("modules", "Modules", "What Aegis runs besides the gate.", modulesBody())}
    ${sec("domain", "Domain", "Where the dashboard and the tunnels live.", domainBody())}
    ${sec("termix", "Termix", "Optional. A terminal for this machine and your servers, behind the same login.", termixBody())}
    ${sec("activity", "Activity", "Every sign-in and failed one, Termix sessions and tunnel changes, with where they came from. Also on this machine: <span class=\"mono\">aegis audit</span>.", activityBody())}
    ${sec("account", "Login", "One login for the dashboard, Termix and every tunnel. A tunnel can also have a password of its own (Burrow → the tunnel → Password).", accountBody())}
    ${sec("apps", "Connected apps", "Apps on this machine that plugged into the dashboard.", integrationsBody())}
    ${advancedBody()}`;
  wireForms();
  landOnHash();
}
// #domain-<zone> (the gear in the dashboards menu) or a section: scrolled to once it's on the
// page (other domains come in a moment later), and a domain's card lights up for a moment
function landOnHash() {
  if (!location.hash || S.scrolled) return;
  const el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
  if (!el) { if (S.doms || !location.hash.startsWith("#domain-")) S.scrolled = true; return; }     // a domain that isn't there (any more): stay put
  S.scrolled = true;
  el.scrollIntoView({ block: el.classList.contains("od-row") ? "center" : "start", behavior: document.readyState === "complete" ? "smooth" : "auto" });
  if (el.classList.contains("od-row")) { el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); }
}

addEventListener("hashchange", () => { S.scrolled = false; landOnHash(); });

function wireForms() {
  const lf = $("#linkForm"), rf = $("#renameForm");
  if (lf || rf) {
    const label = $("#label"), pv = $("#labelPreview");
    const zone = (rf ? S.cf?.domain?.zone : S.cf?.cert?.zone?.name) || "your-zone";
    const upd = () => { S.label = label.value; const v = label.value.trim().toLowerCase() || "aegis"; pv.innerHTML = `Dashboard <b>https://${h(v)}.${h(zone)}</b><br>Tunnels &nbsp;<b>https://tunnel-PORT-${h(v)}.${h(zone)}</b>`; };
    label.addEventListener("input", upd); upd();
  }
  if (rf) rf.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = $("#label").value.trim().toLowerCase(), b = $("#linkGo");
    if (v === S.cf.domain.label) { S.renaming = false; S.label = null; render(); return; }
    if (!confirm(`Move the dashboard to ${v}.${S.cf.domain.zone}? ${S.cf.domain.mainHost} stops working.`)) return;
    b.disabled = true; b.innerHTML = '<i class="spin"></i> Renaming…'; S.busy = true;
    try {
      S.renamedFrom = S.cf.domain.mainHost;
      S.cf = await post("/__gate/api/cf/rename", { label: v });
      const was = location.hostname === S.renamedFrom;
      toast(`The dashboard is now at ${S.cf.domain.mainHost}`);
      S.renaming = false; S.label = null; S.busy = false;
      // on the old address, this page has nowhere left to load from: move to the new one
      if (was) setTimeout(() => { location.href = `https://${S.cf.domain.mainHost}/__gate/settings#domain`; }, 2500);
      else load();
    } catch (ex) { S.busy = false; $("#linkErr").textContent = ex.message; b.disabled = false; b.textContent = "Rename"; }
  });
  if (lf) {
    const label = $("#label");
    lf.addEventListener("submit", async (e) => {
      e.preventDefault();
      const b = $("#linkGo"); b.disabled = true; b.innerHTML = '<i class="spin"></i> Linking…'; S.busy = true;
      try {
        S.cf = await post("/__gate/api/cf/link", { label: label.value.trim().toLowerCase() });
        S.busy = false; S.label = null; toast("Linked. The new address can take a minute to resolve."); load();
      } catch (ex) { S.busy = false; $("#linkErr").textContent = ex.message; b.disabled = false; b.textContent = "Link domain"; }
    });
  }
  $("#odLabel")?.addEventListener("input", (e) => { S.odLabel = e.target.value; });
  $("#odForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const b = $("#odGo"); b.disabled = true; b.innerHTML = '<i class="spin"></i> Adding…'; S.busy = true;
    try {
      const mode = S.odMode || "all", route = S.odRoute || (S.doms.vps ? "vps" : "cloudflare");
      if (mode !== "none" && route === "vps") b.innerHTML = '<i class="spin"></i> Getting the certificate and putting it on your VPS…';
      S.doms = await post("/__gate/api/domains", { label: $("#odLabel").value.trim().toLowerCase(), tunnels: mode, route });
      S.busy = false; S.odLabel = null; S.odMode = null; S.odRoute = null; S.odErr = ""; S.odZone = null; toast(`${S.doms.domains.at(-1)?.zone} added. New names can take a minute to resolve.`); load();
    } catch (ex) { S.busy = false; S.odErr = ex.message; $("#odErr").textContent = ex.message; b.disabled = false; b.textContent = "Try again"; }
  });
  $("#odZone")?.addEventListener("input", (e) => { S.odZone = e.target.value; });
  $("#odCheck")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const b = e.target.querySelector("button"); b.disabled = true; b.innerHTML = '<i class="spin"></i> Checking…';
    try { S.doms = await post("/__gate/api/domains/check", { zone: $("#odZone").value }); S.odErr = ""; }
    catch (ex) { S.odErr = ex.message; }
    document.activeElement?.blur(); render();
  });
  $("#odTokenForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const b = e.target.querySelector("button"); b.disabled = true; b.innerHTML = '<i class="spin"></i> Checking the token…';
    try { S.doms = await post("/__gate/api/domains/token", { zone: S.doms.need.zone, token: $("#odToken").value }); }
    catch (ex) { S.doms = await api("/__gate/api/domains").catch(() => S.doms); toast(ex.message); }
    document.activeElement?.blur(); render();
  });
  $("#odSubName")?.addEventListener("input", (e) => {
    S.odSubName = e.target.value.trim().toLowerCase();
    const f = e.target.closest("form"), z = f.dataset.zone, n = S.odSubName || (S.odSubKind === "one" ? "blog" : "apps"), hint = f.querySelector("p.faint .mono");
    if (hint) hint.textContent = S.odSubKind === "one" ? `${n}.${z}` : `NAME.${n}.${z}`;
  });
  $("#odSubPort")?.addEventListener("change", (e) => { S.odSubPort = e.target.value; });
  document.querySelector(".od-sub-add")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const z = e.target.dataset.zone, x = S.doms.domains.find((d) => d.zone === z), kind = S.odSubKind || "wild";
    const name = $("#odSubName").value.trim().toLowerCase().replace(/^\*\./, "").replace(new RegExp(`\\.${z.replace(/\./g, "\\.")}$`), "");
    const port = Number($("#odSubPort")?.value);
    if (!name) { $("#odSubErr").textContent = "Type the subdomain."; return; }
    const add = kind === "wild" ? { name, wildcard: true } : { name, wildcard: false, port };
    e.target.querySelectorAll("button, input, select").forEach((b) => { b.disabled = true; });
    try {
      await patchSubs(z, [...subsBody(x.subs || []), add], kind === "wild" && x.route === "vps" ? `Getting a certificate for *.${name}.${z} and putting it on your VPS…` : `Adding ${name}.${z}…`);
      S.odSubOpen = null; S.odSubName = ""; S.odSubErr = "";
      toast(kind === "wild" ? `*.${name}.${z} added: tunnels there in a minute` : `${name}.${z} added`);
    } catch (ex) { S.odSubErr = ex.message; }
    document.activeElement?.blur(); render();
  });
  document.querySelector(".od-ren")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const z = e.target.dataset.zone;
    try { S.doms = await api(`/__gate/api/domains/${encodeURIComponent(z)}`, { method: "PATCH", body: JSON.stringify({ label: $("#odRename").value.trim().toLowerCase() }) }); S.odRename = null; toast("Saved"); document.activeElement?.blur(); render(); }
    catch (ex) { toast(ex.message); }
  });
  const sf = $("#siForm");
  if (sf) sf.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      S.me = await post("/__gate/api/prefs", { title: $("#siTitle").value, login: { subtitle: $("#siSub").value },
        sessionDays: Number($("#siDays").value), lockout: { attempts: Number($("#siTries").value), minutes: Number($("#siMins").value) } });
      toast("Saved"); document.activeElement?.blur(); render();
    } catch (ex) { toast(ex.message); }
  });
  $("#nmMode")?.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-v]");
    if (!btn) return;
    S.nmDraft = { ...namingDraft(), mode: btn.dataset.v }; S.nmErr = ""; render();
  });
  $("#nmCerts")?.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-v]");
    if (!btn) return;
    S.nmDraft = { ...namingDraft(), where: btn.dataset.v }; S.nmErr = ""; render();
  });
  $("#nmAccept")?.addEventListener("change", (e) => { S.nmDraft = { ...namingDraft(), accept: e.target.checked }; S.nmErr = ""; render(); });
  const np = $("#nmPrefix");
  if (np) {
    np.addEventListener("input", () => { S.nmDraft = { ...namingDraft(), prefix: np.value.trim().toLowerCase().replace(/^\*?\.|\.$/g, "") }; });
    np.addEventListener("change", () => { np.blur(); render(); });
    np.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); np.blur(); render(); } });
  }
  const nr = $("#nmRelay");
  if (nr) {
    nr.addEventListener("input", () => {
      S.nmDraft = { ...namingDraft(), relay: nr.value.trim() };
      const b = document.querySelector('[data-act="relay-setup"]');
      if (b && !vpsLinked(nr.value.trim())) b.disabled = !IPV4.test(nr.value.trim());
    });
    nr.addEventListener("change", () => { nr.blur(); render(); });
    nr.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); nr.blur(); render(); } });
  }
  const mb = $("#modBurrow");
  if (mb) mb.addEventListener("change", async () => {
    if (!mb.checked && !confirm("Switch Burrow off? Its tunnels stop answering until you switch it back on (they are kept).")) { mb.checked = true; return; }
    try { S.me = await post("/__gate/api/prefs", { modules: { burrow: mb.checked } }); toast(mb.checked ? "Burrow is on" : "Burrow is off"); chrome("settings"); render(); }
    catch (ex) { toast(ex.message); mb.checked = !mb.checked; }
  });
  const mfl = $("#modFleet");
  if (mfl) mfl.addEventListener("change", async () => {
    if (!mfl.checked && !confirm("Switch machine management off? The machines are kept, and so are their keys; nothing here can reach them until you switch it back on.")) { mfl.checked = true; return; }
    try {
      S.me = await post("/__gate/api/prefs", { modules: { fleet: mfl.checked } });
      toast(mfl.checked ? "Machine management is on" : "Machine management is off");
      chrome("settings"); render();
    } catch (ex) { toast(ex.message); mfl.checked = !mfl.checked; }
  });
  const mf = $("#modServeoFwd");
  if (mf) mf.addEventListener("change", async () => {
    try { S.me = await post("/__gate/api/prefs", { serveoForward: mf.checked }); toast(mf.checked ? `The serveo link now sends visitors to ${S.me.domain.mainHost}` : "The serveo link is now a dashboard of its own"); render(); }
    catch (ex) { toast(ex.message); mf.checked = !mf.checked; }
  });
  const ms = $("#modServeo");
  if (ms) ms.addEventListener("change", async () => {
    try {
      S.me = await post("/__gate/api/prefs", { serveo: ms.checked });
      toast(ms.checked ? "Opening a serveo link…" : "Serveo link closed");
      render();
      if (ms.checked) setTimeout(async () => { S.me = await fetch("/__gate/api/me", { credentials: "same-origin" }).then((r) => r.json()); render(); }, 6000);
    } catch (ex) { toast(ex.message); ms.checked = !ms.checked; }
  });
  const au = $("#autoUpd");
  if (au) au.addEventListener("change", async () => {
    try { S.me = await post("/__gate/api/prefs", { autoUpdate: au.checked }); if (S.upd) S.upd.auto = au.checked; toast(au.checked ? "Updates install by themselves" : "Updates wait for you"); render(); }
    catch (ex) { toast(ex.message); au.checked = !au.checked; }
  });
  const adv = document.querySelector(".adv-set");
  if (adv) adv.addEventListener("toggle", () => { S.advOpen = adv.open; });
  for (const row of document.querySelectorAll(".mnt")) {
    const id = row.dataset.mount;
    row.querySelector(".mnt-seg").addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      S.mountDraft = { ...(S.mountDraft || {}), [id]: b.dataset.mnt === "path" ? ($(`#mnt-${id}`)?.value || S.me?.mounts?.[id] || MOUNTS.find((m) => m.id === id).def) : null };
      render();
    });
    const inp = $(`#mnt-${id}`);
    if (inp) inp.addEventListener("input", () => { S.mountDraft = { ...(S.mountDraft || {}), [id]: inp.value }; });
  }
  const mg = $("#mntGo");
  if (mg) mg.addEventListener("click", async () => {
    const body = {};
    for (const m of MOUNTS) if (S.mountDraft && m.id in S.mountDraft) body[m.id] = S.mountDraft[m.id];
    if (!Object.keys(body).length) { toast("Nothing changed"); return; }
    try { S.me = await post("/__gate/api/prefs", { mounts: body }); S.mountDraft = null; toast("Saved. The apps answer at their new places now."); render(); }
    catch (ex) { $("#mntErr").textContent = ex.message; }
  });
  const pf = $("#pwForm");
  if (pf) pf.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#pwErr"), b = $("#pwGo");
    err.textContent = "";
    const username = $("#pwUser").value.trim(), current = $("#pwCur").value, password = $("#pwNew").value;
    if (password.length < 10) { err.textContent = "Use at least 10 characters."; return; }
    if (password !== $("#pwNew2").value) { err.textContent = "The two new passwords differ."; return; }
    b.disabled = true; b.textContent = "Sealing…";
    try {
      if (!window.AegisSeal) throw new Error("The sealing code did not load. Reload the page.");
      const sealed = await window.AegisSeal({ username, current, password });
      await api("/__gate/api/password", { method: "POST", body: JSON.stringify(sealed) });
      toast("Login changed. Other browsers are signed out.");
      pf.reset(); document.activeElement?.blur(); load();
    } catch (ex) { err.textContent = ex.message; }
    b.disabled = false; b.textContent = "Change login";
  });
}

// ------------------------------------------------------------------ activity (the audit log)
function activityBody() {
  const ev = S.audit;
  if (!ev) return '<p class="muted">Loading…</p>';
  if (!ev.length) return '<p class="muted">Nothing yet: sign-ins, Termix sessions and tunnel changes show up here from now on.</p>';
  const bad = (e) => /failed|refused|wrong|throttled|garbled/.test(e);
  const browser = (ua) => !ua ? "" : (/Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl/i.test(ua) ? "curl" : "other")
    + (/Windows/.test(ua) ? " · Windows" : /Android/.test(ua) ? " · Android" : /iPhone|iPad/.test(ua) ? " · iOS" : /CrOS/.test(ua) ? " · ChromeOS" : /Mac OS/.test(ua) ? " · macOS" : /Linux/.test(ua) ? " · Linux" : "");
  const rows = ev.slice(0, S.auditAll ? 300 : 40).map((e) => {
    const { t, event, ip, host, ua, sid, ...x } = e;
    const more = Object.entries(x).map(([k, v]) => `${h(k)}=${h(String(v))}`).join(" ");
    return `<tr><td class="faint mono">${h(t.replace("T", " ").slice(0, 19))}</td>
      <td>${bad(event) ? `<span class="pill err">${h(event)}</span>` : /^sign-in$|password changed/.test(event) ? `<span class="pill ok">${h(event)}</span>` : h(event)}</td>
      <td class="mono">${h(ip)}${ip && ip !== "local" ? ` <button class="btn sm ghost" data-act="audit-ip" data-ip="${h(ip)}">Check</button>` : ""}${S.auditIntel?.[ip] ? ` <span class="pill ${S.auditIntel[ip].level === "malicious" ? "err" : S.auditIntel[ip].level === "suspicious" ? "warn" : "ok"}" title="${h(S.auditIntel[ip].why)}">${h(S.auditIntel[ip].level)}</span>` : ""}</td>
      <td class="faint">${h(browser(ua))}</td><td class="faint small">${more}</td></tr>`;
  }).join("");
  return `<div class="scroll"><table><thead><tr><th>When (UTC)</th><th>What</th><th>From</th><th>Browser</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    ${ev.length > 40 && !S.auditAll ? '<div class="row end" style="margin-top:10px"><button class="btn sm" data-act="audit-all">Show all</button></div>' : ""}`;
}

async function load() {
  try {
    const [me, cf, termix] = await Promise.all([api("/__gate/api/me"), api("/__gate/api/cf"), api("/__gate/api/termix")]);
    S.me = me; S.cf = cf; S.termix = termix;
    S.naming = cf.domain ? await api("/__gate/api/tunnels/naming").catch(() => null) : null;
    S.doms = cf.domain ? await api("/__gate/api/domains").catch(() => null) : null;
    S.relay = cf.domain ? { ...(await api("/__gate/api/relay").catch(() => null)), setup: S.relay?.setup } : null;
    if (S.relay?.configured && !S.doctorBusy) S.doctor = (await api("/__gate/api/relay/doctor").catch(() => null))?.last || null;
    S.tuns = S.doms ? (await api("/__gate/api/tunnels").catch(() => ({ tunnels: [] }))).tunnels || [] : [];
    S.audit = (await api("/__gate/api/audit?n=300").catch(() => ({ events: [] }))).events;
    if (!S.upd && !S.checking) checkUpdates(false);
    if (S.vers === undefined) { S.vers = null; loadVersions(); }
    loadLog(S.log);
  } catch (e) { toast(e.message); }
  render();
  startWorkerPoll();
  clearTimeout(S.poll);
  const vpsWaiting = S.relay?.setup && !setupDone(S.relay) && Date.now() < S.relay.setup.expires;
  if (setupDone(S.relay)) {
    toast(S.relay.checked?.ok ? `${S.relay.vps.host} is linked` : `${S.relay.vps.host} registered, but the link check failed`); S.relay.setup = null; render();
  }
  const waiting = (S.cf?.login && S.cf.login.waiting) || (S.doms?.login && S.doms.login.waiting) || (S.termix?.job && S.termix.job.state === "running") || vpsWaiting;
  S.poll = setTimeout(load, waiting ? 2000 : 8000);
}

async function checkUpdates(force) {
  S.checking = true; render();
  try { S.upd = force ? await post("/__gate/api/update/check") : await api("/__gate/api/update?fresh=1"); }
  catch (e) { S.upd = { error: e.message }; }
  S.checking = false; render();
}

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const act = el.dataset.act;
  try {
    if (act === "login") {
      el.disabled = true; el.innerHTML = '<i class="spin"></i> Asking Cloudflare…';
      const r = await post("/__gate/api/cf/login");
      window.open(r.url, "_blank", "noopener");
      load();
    } else if (act === "cancel-login") { await post("/__gate/api/cf/cancel"); load(); }
    else if (act === "forget") { await post("/__gate/api/cf/forget"); load(); }
    else if (act === "upd-check") { checkUpdates(true); loadVersions(); }
    else if (act === "ver-unhold") { S.vers = await post("/__gate/api/update/hold", { version: null }); render(); toast("Auto-update may install it again"); }
    else if (act === "ver-go") {
      const v = el.dataset.v, cur = S.vers?.current, down = verNewer(cur, v);
      if (!confirm(down ? `Go back from v${cur} to v${v}? Aegis restarts for a few seconds; your login, domain, tunnels and addons are kept. v${cur} is held back from auto-update until a newer version comes.`
                        : `Install v${v}? Aegis restarts for a few seconds; everything you set up is kept.`)) return;
      S.versBusy = `Putting v${v} in place…`; render();
      const before = cur;
      try {
        const r = await post("/__gate/api/update/rollback", { version: v });
        if (r.job?.state === "error") throw new Error(r.job.error);
        if (r.scope === "manual") { S.versBusy = `v${v} is in place. Restart Aegis × Burrow with whatever runs it to finish.`; render(); return; }
        S.versBusy = `v${v} is in place. Restarting…`; render();
        const t0 = Date.now();
        for (;;) {
          await new Promise((ok) => setTimeout(ok, 1500));
          try { const hv = await fetch("/__gate/health", { cache: "no-store" }).then((x) => x.json()); if (hv.version && hv.version !== before) { location.reload(); return; } } catch { /* restarting */ }
          if (Date.now() - t0 > 120000) { S.versBusy = "It is taking a while to come back. Reload in a minute, or run: aegis status"; render(); return; }
        }
      } catch (ex) { S.versBusy = null; toast(ex.message); render(); }
    }
    else if (act === "search") searchOpen();
    else if (act === "upd-go") {
      if (!confirm(`Install Aegis × Burrow v${S.upd.latest}? It restarts for a few seconds; everything you set up is kept.`)) return;
      S.updPhase = "Downloading…"; render();
      try { await runUpdate((t) => { S.updPhase = t; render(); }); }
      catch (ex) { S.updPhase = null; toast(ex.message); render(); }
    }
    else if (act === "log") { S.log = el.dataset.id; render(); loadLog(S.log); }
    else if (act === "rename") { S.renaming = true; S.label = null; render(); $("#label")?.focus(); }
    else if (act === "front-finish") {
      const v = $("#frPaste")?.value.trim();
      if (!v) return;
      el.disabled = true; S.frontLogin = { ...S.frontLogin, status: "exchanging", error: null }; render();
      try {
        const j = await api("/__gate/api/tunnels/front/login/finish", { method: "POST", body: JSON.stringify({ url: v }) });
        if (j.status === "done") { S.frontLogin = null; S.naming = j.naming; S.nmDraft = null; toast(`Cloudflare connected · tunnels live under ${j.naming.record || "their names"}`); }
      } catch (ex) { S.frontLogin = S.frontLogin && { ...S.frontLogin, status: "waiting", error: ex.message }; }
      render(); followFrontLogin();
    }
    else if (act === "audit-all") { S.auditAll = true; render(); }
    else if (act === "audit-ip") {
      el.disabled = true; el.innerHTML = '<i class="spin"></i>';
      try { const r = await api(`/__gate/api/ipintel/${encodeURIComponent(el.dataset.ip)}`); S.auditIntel = { ...(S.auditIntel || {}), [el.dataset.ip]: { level: r.verdict.level, why: [r.owner?.org, ...r.verdict.why].filter(Boolean).join(" · ") } }; }
      catch (ex) { toast(ex.message); }
      render();
    }
    else if (act === "front-cancel") { clearTimeout(S.frontPoll); S.frontLogin = null; render(); }
    else if (act === "front-token") {
      const v = $("#frToken")?.value.trim();
      if (!v) return;
      el.disabled = true;
      try { S.naming = await api("/__gate/api/tunnels/front", { method: "PUT", body: JSON.stringify({ token: v }) }); toast("Cloudflare Workers connected"); }
      catch (ex) { S.nmErr = ex.message; }
      render();
    }
    else if (act === "naming-cancel") { S.nmDraft = null; S.nmErr = ""; render(); }
    else if (act === "relay-setup") {
      const n = namingDraft();
      if (!IPV4.test(n.relay)) { S.nmErr = "Type your VPS's public IPv4 address first, like 203.0.113.7."; render(); return; }
      if (vpsLinked(n.relay) && !confirm(`Reinstall the agent on ${n.relay}? The link stays as it is until the new install registers.`)) return;
      el.disabled = true;
      try {
        const r = await api("/__gate/api/relay/setup", { method: "POST", body: JSON.stringify({ host: n.relay, prefix: n.prefix }) });
        S.relay = { ...(S.relay || {}), setup: { ...r, created: Date.now() } }; S.nmErr = "";
      } catch (ex) { S.nmErr = ex.message; }
      render(); clearTimeout(S.poll); S.poll = setTimeout(load, 2500);
    }
    else if (act === "relay-copy") {
      const v = S.relay?.setup?.command || "";
      try { await navigator.clipboard.writeText(v); toast("Copied: paste it in your VPS's terminal"); }
      catch { const i = $("#vpsCmd"); i?.select(); toast("Select-all is on: copy it with Ctrl+C"); }
    }
    else if (act === "relay-check") {
      S.vpsChecking = true; render();
      try { S.relay = { ...(await api("/__gate/api/relay/check", { method: "POST", body: "{}" })), setup: S.relay?.setup }; toast(S.relay.checked?.ok ? "The VPS answers through the link" : "Couldn't reach the VPS"); }
      catch (ex) { toast(ex.message); }
      S.vpsChecking = false; render();
    }
    else if (act === "relay-doctor") {
      S.doctorBusy = true; render();
      try { S.doctor = (await api("/__gate/api/relay/doctor", { method: "POST", body: "{}" })).last; toast(S.doctor?.ok ? "Visitors get through your VPS" : "Not reachable yet: see below"); }
      catch (ex) { toast(ex.message); }
      S.doctorBusy = false; render();
    }
    else if (act === "relay-forget") {
      if (S.naming?.active && S.naming.certs === "self" && S.naming.route === "vps") { toast("The tunnels go through this VPS: move them elsewhere first"); return; }
      if (!confirm("Forget this VPS? This Aegis stops trusting it. (To remove the agent there too: systemctl disable --now aegis-relay-agent; userdel -r aegis-relay)")) return;
      S.relay = { ...(await api("/__gate/api/relay/forget", { method: "POST", body: "{}" })), setup: null }; toast("Forgotten"); render();
    }
    else if (act === "naming-save") {
      const d = namingDraft(), n = namingBody(d), zone = S.cf.domain.zone;
      const names = `NAME.${n.prefix ? n.prefix + "." : ""}${zone}`;
      const where = n.mode !== "wildcard" ? `tunnel-PORT-${S.cf.domain.mainHost} with a DNS record each`
        : d.where === "vps" ? `${names}, through your VPS ${d.relay}` : d.where === "home" ? `${names}, straight to this machine` : `${names} through one wildcard record`;
      const sameNames = S.naming.active && n.mode === "wildcard" && n.prefix === S.naming.prefix;
      if (!confirm(sameNames ? `Move every tunnel to ${where}? Their addresses stay the same; for a few seconds while DNS updates, some visitors may not get through.` : `Move every tunnel to ${where}? Their current addresses stop working.`)) return;
      if (n.mode === "wildcard" && n.certs === "worker" && !S.naming.front?.linked) { S.nmErr = ""; return frontConnect(n); }
      el.disabled = true; el.innerHTML = n.mode === "wildcard" && d.where === "vps" ? '<i class="spin"></i> Linking the VPS and handing it the certificate…'
        : n.mode === "wildcard" && (n.certs === "self" || n.certs === "worker") ? '<i class="spin"></i> Setting up the certificates…' : '<i class="spin"></i> Moving…'; S.busy = true;
      try {
        const j = await api("/__gate/api/tunnels/naming", { method: "PUT", body: JSON.stringify(n) });
        S.naming = j; S.nmDraft = null; S.nmErr = "";
        toast(j.active ? `Tunnels now live under ${j.record}` : "Tunnels have a DNS record each again");
      } catch (ex) { S.nmErr = ex.message; }
      finally { S.busy = false; }
      render();
    }
    else if (act === "od-login") {
      el.disabled = true; el.innerHTML = '<i class="spin"></i> Asking Cloudflare…';
      const r = await post("/__gate/api/domains/login");
      window.open(r.url, "_blank", "noopener");
      load();
    }
    else if (act === "od-cancel") { S.doms = await post("/__gate/api/domains/cancel"); render(); }
    else if (act === "od-forget") { S.doms = await post("/__gate/api/domains/forget"); S.odErr = ""; S.odMode = S.odRoute = S.odLabel = null; render(); }
    else if (act === "od-mode") { S.odMode = el.dataset.v; render(); }
    else if (act === "od-route-new") { S.odRoute = el.dataset.v; render(); }
    else if (act === "od-route") {
      const z = el.dataset.zone, v = el.dataset.v;
      if (v === "vps" && !confirm(`Send ${z}'s tunnels straight to your VPS? Aegis gets a certificate for *.${z}, puts it on ${S.doms.vps?.host || "the VPS"}, then points *.${z} there.`)) return;
      el.closest(".od-t").insertAdjacentHTML("beforeend", `<span class="faint small"><i class="spin"></i> ${v === "vps" ? "Getting the certificate and putting it on your VPS…" : "Moving…"}</span>`);
      S.busy = true;
      try { S.doms = await api(`/__gate/api/domains/${encodeURIComponent(z)}`, { method: "PATCH", body: JSON.stringify({ route: v }) }); toast(v === "vps" ? `${z}'s tunnels now go through your VPS` : `${z}'s tunnels now go through Cloudflare`); }
      finally { S.busy = false; }
      render();
    }
    else if (act === "od-ren") { S.odRename = el.dataset.zone; render(); $("#odRename")?.focus(); }
    else if (act === "od-sub-open") { S.odSubOpen = el.dataset.zone; S.odSubErr = ""; S.odSubName = ""; S.odSubKind = S.odSubKind || "wild"; render(); $("#odSubName")?.focus(); }
    else if (act === "od-sub-cancel") { S.odSubOpen = null; S.odSubErr = ""; document.activeElement?.blur(); render(); }
    else if (act === "od-sub-kind") {             // the box may still have focus (Safari doesn't focus buttons): repaint anyway
      S.odSubKind = el.dataset.v; S.odSubErr = ""; if (!S.odSubPort && S.tuns?.length) S.odSubPort = S.tuns[0].port;
      document.activeElement?.blur(); render(); $("#odSubName")?.focus();
    }
    else if (act === "od-sub-rm") {
      const z = el.dataset.zone, n = el.dataset.name, x = S.doms.domains.find((d) => d.zone === z), s = (x.subs || []).find((y) => y.name === n);
      if (!confirm(`Remove ${s.host}? ${s.wildcard ? `Tunnel names under it stop working, and your VPS lets go of its certificate.` : "That name stops working; the tunnel itself stays."}`)) return;
      try { await patchSubs(z, subsBody(x.subs.filter((y) => y.name !== n)), `Removing ${s.host}…`); toast(`${s.host} removed`); }
      catch (ex) { toast(ex.message); }
      render();
    }
    else if (act === "od-ren-cancel") { S.odRename = null; render(); }
    else if (act === "od-tunnels") {
      S.doms = await api(`/__gate/api/domains/${encodeURIComponent(el.dataset.zone)}`, { method: "PATCH", body: JSON.stringify({ tunnels: el.dataset.v }) });
      toast(el.dataset.v === "none" ? `Only the dashboard on ${el.dataset.zone}` : `Tunnels on ${el.dataset.zone}: ${el.dataset.v === "all" ? "all of them" : "the ones you pick"}`); render();
    }
    else if (act === "od-remove") {
      const z = el.dataset.zone;
      if (!confirm(`Remove ${z}? Its dashboard and tunnel names stop working; Aegis deletes its records and its Cloudflare tunnel. ${S.cf.domain.zone} is not touched.`)) return;
      el.disabled = true; el.innerHTML = '<i class="spin"></i> Removing…'; S.busy = true;
      try { S.doms = await api(`/__gate/api/domains/${encodeURIComponent(z)}`, { method: "DELETE" }); toast(`${z} removed`); } finally { S.busy = false; }
      render();
    }
    else if (act === "rename-cancel") { S.renaming = false; S.label = null; render(); }
    else if (act === "unlink") {
      if (!confirm(`Unlink ${S.cf.domain.mainHost}? Its DNS records and the Cloudflare tunnel are deleted, and tunnels go back to trycloudflare.com names.`)) return;
      el.disabled = true; el.innerHTML = '<i class="spin"></i> Unlinking…'; S.busy = true;
      try { S.cf = await post("/__gate/api/cf/unlink"); toast("Unlinked"); } finally { S.busy = false; }
      load();
    } else if (act === "termix-install") {
      el.disabled = true; await post("/__gate/api/termix/install"); toast("Installing Termix…"); load();
    } else if (act === "termix-remove") {
      if (!confirm("Remove the Termix container? Its data volume is kept.")) return;
      await post("/__gate/api/termix/remove"); toast("Termix removed"); chrome("settings"); load();
    }
  } catch (ex) { toast(ex.message); load(); }
});

chrome("settings");
load();
