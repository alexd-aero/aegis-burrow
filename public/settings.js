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
function domainBody() {
  const cf = S.cf;
  if (!cf) return '<p class="muted">Loading…</p>';
  if (cf.domain) {
    const d = cf.domain, c = cf.connector;
    return `<div class="linked">
        <div class="kv-row"><span>Dashboard</span><a class="mono" href="https://${h(d.mainHost)}" target="_blank" rel="noopener">https://${h(d.mainHost)}</a></div>
        <div class="kv-row"><span>Tunnels</span><span><span class="mono">tunnel-PORT-${h(d.mainHost)}</span> <span class="faint small">or a name of your own per tunnel (Burrow → a tunnel → Edit)</span></span></div>
        <div class="kv-row"><span>Connector</span>${!d.managed ? '<span class="pill">your own cloudflared service</span>'
          : c && c.running ? `<span class="pill ok"><i class="dot ok"></i>connected · post-quantum · since ${h(ago(c.since))}</span>` : '<span class="pill err"><i class="dot err"></i>not running</span>'}</div>
      </div>
      ${c && c.log && c.log.length ? `<details class="adv"><summary>Connector log</summary><pre class="log">${h(c.log.join("\n"))}</pre></details>` : ""}
      ${S.renaming ? `<form id="renameForm" class="link-form" autocomplete="off">
          <label class="field"><span>New name for the dashboard</span>
            <div class="addr"><input class="input mono" id="label" value="${h(S.label ?? d.label)}" maxlength="40" spellcheck="false" autocapitalize="none"><span class="mono zone">.${h(d.zone)}</span></div></label>
          <div class="preview" id="labelPreview"></div>
          <p class="faint small">The old address stops working, so this page moves to the new one and you sign in there again. Tunnels named tunnel-PORT-… move with it; tunnels with a name of their own keep it.${d.managed ? "" : " Your own cloudflared service must already send the new name here (a *." + h(d.zone) + " rule in its ingress does); Aegis checks before it changes anything."}</p>
          <div class="err-msg" id="linkErr"></div>
          <div class="row end"><button type="button" class="btn ghost" data-act="rename-cancel">Cancel</button><button class="btn primary" id="linkGo">Rename</button></div>
        </form>`
      : d.managed ? `<div class="row end"><button class="btn" data-act="rename">Change the name</button><button class="btn danger" data-act="unlink">Unlink ${h(d.mainHost)}</button></div>`
        : `<p class="faint small">This address is routed by a cloudflared service Aegis did not create; Aegis manages the DNS records (the dashboard's and one per tunnel).</p>
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
    </div>`;
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
  ["Serveo link", "modules", "public link serveousercontent phone url temporary"],
  ["Serveo link: send visitors on to the domain", "modules", "forward redirect serveo domain"],
  ["The full pack", "modules", "termix forge install welcome first run"],
  ["Domain", "domain", "cloudflare dns link custom domain address"],
  ["Change the dashboard's name (subdomain)", "domain", "rename subdomain name aegis private"],
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
  if (focusId && (["label", "pwUser", "pwCur", "pwNew", "pwNew2", "siTitle", "siSub", "siDays", "siTries", "siMins"].includes(focusId) || focusId.startsWith("mnt-"))) return;   // never repaint under typing
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
    ${sec("account", "Login", "One login for the dashboard, Termix and every tunnel. A tunnel can also have a password of its own (Burrow → the tunnel → Password).", accountBody())}
    ${sec("apps", "Connected apps", "Apps on this machine that plugged into the dashboard.", integrationsBody())}
    ${advancedBody()}`;
  wireForms();
  if (location.hash && !S.scrolled) { S.scrolled = true; document.querySelector(location.hash)?.scrollIntoView({ block: "start" }); }
}

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
  const sf = $("#siForm");
  if (sf) sf.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      S.me = await post("/__gate/api/prefs", { title: $("#siTitle").value, login: { subtitle: $("#siSub").value },
        sessionDays: Number($("#siDays").value), lockout: { attempts: Number($("#siTries").value), minutes: Number($("#siMins").value) } });
      toast("Saved"); document.activeElement?.blur(); render();
    } catch (ex) { toast(ex.message); }
  });
  const mb = $("#modBurrow");
  if (mb) mb.addEventListener("change", async () => {
    if (!mb.checked && !confirm("Switch Burrow off? Its tunnels stop answering until you switch it back on (they are kept).")) { mb.checked = true; return; }
    try { S.me = await post("/__gate/api/prefs", { modules: { burrow: mb.checked } }); toast(mb.checked ? "Burrow is on" : "Burrow is off"); chrome("settings"); render(); }
    catch (ex) { toast(ex.message); mb.checked = !mb.checked; }
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

async function load() {
  try {
    const [me, cf, termix] = await Promise.all([api("/__gate/api/me"), api("/__gate/api/cf"), api("/__gate/api/termix")]);
    S.me = me; S.cf = cf; S.termix = termix;
    if (!S.upd && !S.checking) checkUpdates(false);
    loadLog(S.log);
  } catch (e) { toast(e.message); }
  render();
  clearTimeout(S.poll);
  const waiting = (S.cf?.login && S.cf.login.waiting) || (S.termix?.job && S.termix.job.state === "running");
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
    else if (act === "upd-check") checkUpdates(true);
    else if (act === "search") searchOpen();
    else if (act === "upd-go") {
      if (!confirm(`Install Aegis × Burrow v${S.upd.latest}? It restarts for a few seconds; everything you set up is kept.`)) return;
      S.updPhase = "Downloading…"; render();
      try { await runUpdate((t) => { S.updPhase = t; render(); }); }
      catch (ex) { S.updPhase = null; toast(ex.message); render(); }
    }
    else if (act === "log") { S.log = el.dataset.id; render(); loadLog(S.log); }
    else if (act === "rename") { S.renaming = true; S.label = null; render(); $("#label")?.focus(); }
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
