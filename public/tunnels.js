// Tunnel manager UI. No inline handlers (strict CSP): everything is wired
// through data-act attributes and one delegated listener.
import { chrome } from "./common.js";
import { distroLogo, distroLabel } from "./distros.js";

const $ = (s, el = document) => el.querySelector(s);
const app = $("#app");
const S = { view: "list", port: null, list: [], detail: null, ports: null, timer: null, busy: false, modal: null, lastOk: 0,
            mode: "domain", pattern: "", integrations: [], integ: null, integData: null, forgeSummary: {}, addon: null,
            addons: null, scan: null, scanning: false, bridge: null, bridgeBusy: false };

const h = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => n == null ? "–" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e4 ? (n / 1e3).toFixed(1) + "k" : Math.round(n).toLocaleString();
const fmtB = (b) => { if (!b) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(4, Math.floor(Math.log(b) / Math.log(1024))); return (b / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i]; };
const fmtMs = (ms) => ms == null ? "–" : ms < 1000 ? Math.round(ms) + " ms" : (ms / 1000).toFixed(1) + " s";
const ago = (t) => { if (!t) return "never"; const s = Math.max(0, (Date.now() - t) / 1000); return s < 5 ? "now" : s < 60 ? Math.floor(s) + "s ago" : s < 3600 ? Math.floor(s / 60) + "m ago" : s < 86400 ? Math.floor(s / 3600) + "h ago" : Math.floor(s / 86400) + "d ago"; };
const clock = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const flag = (cc) => /^[A-Z]{2}$/.test(cc || "") && cc !== "XX" && cc !== "T1" ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) : "";
const displayName = (t) => t.name || t.title || (t.site ? t.site.url.replace(/^https:\/\//, "") : `tunnel-${t.port}`);

const ICON = {
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>',
  ext: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>',
  back: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L19 9l-4-4L4 16v4z"/></svg>',
  tunnel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 18 0"/><path d="M7 12a5 5 0 0 1 10 0"/><circle cx="12" cy="12" r="1.5"/><path d="M12 13.5V20"/></svg>',
  lock: '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  globe: '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
  chev: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M7 4.5v15l12.5-7.5z"/></svg>',
  stop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
  restart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 4v5h-5"/></svg>',
  desk: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
  plug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 7V3M15 7V3M6 7h12v4a6 6 0 0 1-12 0zM12 17v4"/></svg>',
  up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>',
  box: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 5.5V11c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V5.5z"/></svg>',
  key: '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 8.7-8.7M17 6l3 3M14.5 8.5l2 2"/></svg>',
  term: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m5 8 4 4-4 4M12 16h7"/></svg>',
};

// ------------------------------------------------------------------ api
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Gate": "1", ...(opts.headers || {}) } });
  if (r.status === 401) { location.href = "/__gate/login"; throw new Error("Signed out"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
function setLive(ok, text) {
  const el = $("#liveState");
  el.innerHTML = `<i class="dot ${ok ? "ok" : "err"}"></i><span>${h(text)}</span>`;
}
function toast(msg) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg; document.body.append(t);
  setTimeout(() => t.remove(), 2600);
}

// ------------------------------------------------------------------ charts
function spark(values, w = 320, hgt = 44) {
  const max = Math.max(1, ...values);
  const step = w / Math.max(1, values.length - 1);
  const pts = values.map((v, i) => [i * step, hgt - 3 - (v / max) * (hgt - 8)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const id = "g" + Math.random().toString(36).slice(2, 8);
  const flat = values.every((v) => !v);
  return `<svg class="spark" viewBox="0 0 ${w} ${hgt}" preserveAspectRatio="none" aria-hidden="true">
    <defs><linearGradient id="${id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".16"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient></defs>
    <path d="${line} L${w} ${hgt} L0 ${hgt} Z" fill="url(#${id})"/>
    <path d="${line}" fill="none" stroke="${flat ? "#3a3d42" : "#e8eaed"}" stroke-width="1.4" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
  </svg>`;
}
function bars(data, key, { errKey, w = 720, hgt = 150, color = "#d7dade" } = {}) {
  const max = Math.max(1, ...data.map((d) => d[key]));
  const bw = w / data.length;
  let out = `<svg class="chart" viewBox="0 0 ${w} ${hgt}" preserveAspectRatio="none" role="img" aria-label="chart">`;
  for (const f of [0.25, 0.5, 0.75]) out += `<line x1="0" x2="${w}" y1="${(hgt * f).toFixed(1)}" y2="${(hgt * f).toFixed(1)}" stroke="rgba(255,255,255,.05)" vector-effect="non-scaling-stroke"/>`;
  data.forEach((d, i) => {
    const v = d[key], bh = (v / max) * (hgt - 6);
    if (v) out += `<rect x="${(i * bw + bw * 0.15).toFixed(2)}" y="${(hgt - bh).toFixed(2)}" width="${(bw * 0.7).toFixed(2)}" height="${bh.toFixed(2)}" rx="1" fill="${color}" fill-opacity=".72"><title>${h(clock(d.t))}: ${fmtN(v)}</title></rect>`;
    if (errKey && d[errKey]) { const eh = (d[errKey] / max) * (hgt - 6); out += `<rect x="${(i * bw + bw * 0.15).toFixed(2)}" y="${(hgt - eh).toFixed(2)}" width="${(bw * 0.7).toFixed(2)}" height="${eh.toFixed(2)}" rx="1" fill="#ff5a52"/>`; }
  });
  return out + "</svg>";
}
function lines(data, keys, colors, { w = 720, hgt = 150 } = {}) {
  const max = Math.max(1, ...data.flatMap((d) => keys.map((k) => d[k])));
  const step = w / Math.max(1, data.length - 1);
  let out = `<svg class="chart" viewBox="0 0 ${w} ${hgt}" preserveAspectRatio="none" aria-hidden="true">`;
  for (const f of [0.25, 0.5, 0.75]) out += `<line x1="0" x2="${w}" y1="${(hgt * f).toFixed(1)}" y2="${(hgt * f).toFixed(1)}" stroke="rgba(255,255,255,.05)" vector-effect="non-scaling-stroke"/>`;
  keys.forEach((k, j) => {
    const d = data.map((p, i) => (i ? "L" : "M") + (i * step).toFixed(1) + " " + (hgt - 3 - (p[k] / max) * (hgt - 8)).toFixed(1)).join(" ");
    out += `<path d="${d} L${w} ${hgt} L0 ${hgt} Z" fill="${colors[j]}" fill-opacity=".06"/><path d="${d}" fill="none" stroke="${colors[j]}" stroke-width="1.5" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
  });
  return out + "</svg>";
}

// ------------------------------------------------------------------ pieces
function fav(t, lg) {
  const letter = h((displayName(t)[0] || "T").toUpperCase());
  return `<div class="fav${lg ? " lg" : ""}">${t.favicon ? `<img src="${h(t.favicon)}" alt="" data-fallback="${letter}">` : letter}</div>`;
}
function statusPill(t) {
  if (!t.enabled) return '<span class="pill">paused</span>';
  if (t.quick && t.quick.state === "error") return `<span class="pill err" title="${h(t.quick.error)}">no address</span>`;
  if (!t.url) return '<span class="pill warn"><i class="dot warn"></i>getting an address</span>';
  if (t.dns && t.dns.error) return `<span class="pill err" title="${h(t.dns.error)}">DNS error</span>`;
  if (t.health.up === false) return '<span class="pill err"><i class="dot err"></i>target down</span>';
  if (t.health.up === null) return '<span class="pill">checking</span>';
  return `<span class="pill ok"><i class="dot ok"></i>live · ${fmtMs(t.health.ms)}</span>`;
}
const accessPill = (t) => t.access === "public" ? `<span class="pill warn">${ICON.globe} public</span>`
  : t.access === "password" ? `<span class="pill lock">${ICON.key} password</span>` : `<span class="pill lock">${ICON.lock} login</span>`;
// where it goes: a port, or a Pages site
const targetPill = (t) => t.meta?.repo ? `<span class="pill site">${h(PROVIDER[t.meta.provider] ? PROVIDER[t.meta.provider].replace(" Pages", "") : "repo")} · ${h(t.meta.repo)}${t.meta.branch ? ` @${h(t.meta.branch)}` : ""}</span>`
  : t.kind === "site" ? `<span class="pill site">${h(PROVIDER[t.site.provider] || "Pages")} · ${h(t.site.url.replace(/^https:\/\//, "").replace(/\/$/, ""))}</span>`
  : `<span class="pill">→ ${h(t.targetHost)}:${t.targetPort}</span>`;

function card(t) {
  return `<article class="card tcard${t.enabled ? "" : " off"}" data-act="open" data-port="${t.port}">
    <div class="t-top">
      ${fav(t)}
      <div class="grow">
        <div class="t-name">${h(displayName(t))}</div>
        <div class="t-url">${t.url ? `<a href="${h(t.url)}" target="_blank" rel="noopener" data-stop>${h(t.host)}</a>
          <button class="copy" data-act="copy" data-text="${h(t.url)}" title="Copy link" aria-label="Copy link">${ICON.copy}</button>` : `<span class="faint">port ${t.port} · waiting for trycloudflare.com</span>`}</div>
      </div>
      <label class="switch" title="${t.enabled ? "On" : "Off"}" data-stop><input type="checkbox" data-act="toggle" data-port="${t.port}" ${t.enabled ? "checked" : ""} aria-label="Tunnel on or off"><i></i></label>
    </div>
    <div class="t-meta">${statusPill(t)}${accessPill(t)}${targetPill(t)}${t.wsActive ? `<span class="pill">${t.wsActive} ws</span>` : ""}</div>
    ${spark(t.spark)}
    <div class="t-nums">
      <div><b>${fmtN(t.reqPerMin)}</b><span>req/min</span></div>
      <div><b>${fmtN(t.active)}</b><span>active</span></div>
      <div><b>${fmtN(t.online)}<span class="faint">/${fmtN(t.clients)}</span></b><span>clients</span></div>
      <div><b>${fmtB(t.totals.bytesOut)}</b><span>served</span></div>
    </div>
  </article>`;
}

// ------------------------------------------------------------------ views
// Tunnels | Addons | Selkies Forge: the sides of the Burrow page.
function subtabs() {
  const a = S.addon, linked = !!(a && a.addon), upd = !!(a && a.addon && a.addon.update && a.addon.update.available);
  const b = S.bridge, dot = b ? { ok: "ok", warn: "warn", fail: "err", off: "idle" }[b.state] : linked ? "ok" : "idle";
  const installed = S.addons ? S.addons.filter((x) => x.installed).length : null;
  // the Selkies Forge side only when a Forge is on this machine (or already runs us)
  const forgeReal = S.integrations.some((i) => i.full) || !!(a && (a.forge || a.addon));
  const forgeHere = forgeReal || S.view === "forge";
  return `<nav class="subtabs" aria-label="Burrow">
    <button data-act="tab" data-v="list" class="${S.view === "list" ? "on" : ""}">${ICON.tunnel}Tunnels${S.off ? "" : `<span class="count">${S.list.length}</span>`}</button>
    <button data-act="tab" data-v="addons" class="${S.view === "addons" ? "on" : ""}">${ICON.box}Addons${installed != null ? `<span class="count">${installed}</span>` : ""}</button>
    ${forgeHere ? `<button data-act="tab" data-v="forge" class="${S.view === "forge" ? "on" : ""}"><img class="tab-logo" src="/__gate/logos/forge.svg" alt="">Selkies Forge${forgeReal && (a || b) ? `<i class="dot ${dot}"></i>` : ""}${upd ? '<span class="newchip">update</span>' : ""}</button>` : ""}
  </nav>`;
}

function renderList() {
  const L = S.list;
  if (S.off) {
    app.innerHTML = `<div class="head"><div><h1>Connected apps</h1><p>Burrow (tunnels) is switched off. <a class="link" href="/__gate/settings#modules">Turn it on</a> to publish ports.</p></div></div>
      ${subtabs()}
      ${S.integrations.map(integCard).join("") || '<p class="muted">Nothing has plugged in yet.</p>'}`;
    return;
  }
  const on = L.filter((t) => t.enabled).length;
  const sum = (f) => L.reduce((a, t) => a + f(t), 0);
  const sites = L.filter(isSite), ports = L.filter((t) => !isSite(t));
  app.innerHTML = `
    <div class="head">
      <div><h1>Burrow</h1><p>${S.mode === "domain"
        ? `Publish any port at <span class="mono">${h(S.pattern)}</span>, behind the same post-quantum login.`
        : `Publish any port on ${h(S.pattern)}, behind the same post-quantum login. <a class="link" href="/__gate/settings#domain">Use your own domain</a>`}</p></div>
      <div class="spacer"></div>
      <button class="btn primary" data-act="new">${ICON.plus} New tunnel</button>
    </div>
    ${subtabs()}
    <div class="stats">
      <div class="card stat"><b>${on}<span class="faint">/${L.length}</span></b><span>tunnels live</span></div>
      <div class="card stat"><b>${fmtN(sum((t) => t.reqPerMin))}</b><span>requests / min</span><div class="sub">${fmtN(sum((t) => t.totals.requests))} total</div></div>
      <div class="card stat"><b>${fmtN(sum((t) => t.online))}</b><span>clients online</span><div class="sub">${fmtN(sum((t) => t.active))} open connections</div></div>
      <div class="card stat"><b>${fmtB(sum((t) => t.totals.bytesOut))}</b><span>served</span><div class="sub">${fmtB(sum((t) => t.totals.bytesIn))} received</div></div>
    </div>
    ${S.integrations.map(integCard).join("")}
    ${panels()}
    ${!PANELS.has("burrow-pages") && sites.length ? pagesCard(sites) : ""}
    ${ports.length ? `<div class="grid">${ports.map(card).join("")}</div>` : `
    <div class="card lit empty">
      <div class="big">${ICON.tunnel}</div>
      <h2>No tunnels yet</h2>
      <p>Pick a port running on this machine (or anywhere it can reach) and it gets its own HTTPS address in seconds. Login-protected by default.</p>
      <button class="btn primary" data-act="new">${ICON.plus} New tunnel</button>
    </div>`}`;
}

// ------------------------------------------------------------------ Burrow Pages
// The Burrow Pages addon (github.com/alexd-aero/burrow-pages): GitHub and
// GitLab Pages sites on a subdomain of yours, behind a password. Its sites
// live on this card, not among the ports.
const pagesOn = () => !!S.me?.pages?.installed;
const isSite = (t) => t.kind === "site" || t.app === "burrow-pages";

// Panels that addons bring for this page (their manifest's "burrow": {"ui"}).
// A panel is an ES module: card(ctx) -> HTML, wire(el, ctx) after each paint.
const PANELS = new Map();          // id -> module
const panelWant = new Set();
function loadPanels() {
  for (const x of S.me?.extensions || []) {
    if (panelWant.has(x.ui)) continue;
    panelWant.add(x.ui);
    import(x.ui).then((m) => { PANELS.set(x.id, m); render(); }).catch((e) => console.warn(`panel ${x.id}:`, e));
  }
}
function panelCtx(id) {
  return { id, api: (p, o) => api(`/__gate/api/x/${id}${p}`, o), h, toast, openModal, closeModal, refresh, render, go, ICON, ago, fmtN,
           fav, statusPill, accessPill, targetPill, displayName, siteRow, accessSeg, pwFields, sealedPw, tunnelForm,
           tunnels: S.list.filter((t) => t.app === id || (id === "burrow-pages" && t.kind === "site")),
           mode: S.mode, zone: zoneName(), me: S.me };
}
function panels() {
  return [...PANELS].map(([id, m]) => {
    try { return `<div class="panel-slot" data-panel="${h(id)}">${m.card(panelCtx(id))}</div>`; }
    catch (e) { console.warn(e); return ""; }
  }).join("");
}
function wirePanels() {
  for (const el of document.querySelectorAll("[data-panel]")) {
    const m = PANELS.get(el.dataset.panel);
    try { m?.wire?.(el, panelCtx(el.dataset.panel)); } catch (e) { console.warn(e); }
  }
}
function siteRow(t) {
  return `<div class="prow${t.enabled ? "" : " off"}" data-act="open" data-port="${t.port}" role="link" tabindex="0">
    ${fav(t)}
    <div class="grow"><div class="t-name">${h(displayName(t))}</div>
      <div class="t-url">${t.url ? `<a href="${h(t.url)}" target="_blank" rel="noopener" data-stop>${h(t.host)}</a>
        <button class="copy" data-act="copy" data-text="${h(t.url)}" title="Copy link" aria-label="Copy link">${ICON.copy}</button>` : '<span class="faint">getting an address…</span>'}</div></div>
    <div class="t-meta prow-meta">${statusPill(t)}${accessPill(t)}${targetPill(t)}</div>
    <label class="switch" title="${t.enabled ? "On" : "Off"}" data-stop><input type="checkbox" data-act="toggle" data-port="${t.port}" ${t.enabled ? "checked" : ""} aria-label="Site on or off"><i></i></label>
  </div>`;
}
function pagesCard(sites) {
  const p = S.me?.pages || {}, on = pagesOn();
  return `<section class="card lit pages" id="pagesCard">
    <div class="pages-head">
      <div class="integ-logo"><img src="${h(p.logo || "/__gate/logos/burrow-pages.svg")}" alt=""></div>
      <div class="grow">
        <div class="integ-name">Burrow Pages ${p.version ? `<span class="pill">v${h(p.version)}</span>` : ""}<span class="pill exp">experimental</span></div>
        <div class="integ-sub">${on ? "GitHub &amp; GitLab Pages on your domain, behind your login or a password of their own." : "Not installed: these sites keep their settings, paused, until it is back."}</div>
      </div>
      ${on ? `<button class="btn sm primary" data-act="site-new">${ICON.plus} Add a site</button>` : `<button class="btn sm" data-act="tab" data-v="addons">Install it</button>`}
    </div>
    ${sites.length ? `<div class="pages-list">${sites.map(siteRow).join("")}</div>`
      : `<div class="pages-empty"><p class="muted small">No sites yet. Paste a <span class="mono">you.github.io/project</span> or <span class="mono">gitlab.com/group/project</span> address, pick a subdomain, and it answers there, only to whoever has the password.</p></div>`}
  </section>`;
}

// ------------------------------------------------------------------ integrations
// A wide card per app that plugged itself in (see aegis/integrations.mjs).
function integCard(i) {
  const sum = S.forgeSummary[i.id];
  const sub = i.full
    ? (sum ? (sum.reachable ? `${sum.desktops} desktop${sum.desktops === 1 ? "" : "s"} · ${sum.running} running` : "not answering") : "desktops, links and tunnels")
    : "connected app";
  return `<article class="card lit integ" data-act="integ" data-id="${h(i.id)}" tabindex="0" role="link" aria-label="${h(i.name)}">
    <div class="integ-logo">${i.logo ? `<img src="${h(i.logo)}" alt="">` : h(i.name[0])}</div>
    <div class="grow">
      <div class="integ-name">${h(i.name)} ${i.version ? `<span class="pill">v${h(i.version)}</span>` : ""}</div>
      <div class="integ-sub">${sum && !sum.reachable ? '<i class="dot err"></i>' : sum ? '<i class="dot ok"></i>' : ""}${h(sub)}</div>
    </div>
    <a class="btn sm" href="${h(i.dashboard)}" target="_blank" rel="noopener" data-stop>${ICON.ext} Dashboard</a>
    <span class="integ-go" aria-hidden="true">${ICON.chev}</span>
  </article>`;
}

function deskLinks(d) {
  const row = (label, url, extra = "") => `<div class="dl-row"><span class="dl-k">${label}</span>
    <a class="mono" href="${h(url)}" target="_blank" rel="noopener">${h(url.replace(/^https?:\/\//, "").replace(/\/$/, ""))}</a>
    <button class="copy" data-act="copy" data-text="${h(url)}" aria-label="Copy link">${ICON.copy}</button>${extra}</div>`;
  const out = [];
  if (d.tunnel && d.tunnel.url) out.push(row("Tunnel", d.tunnel.url, d.tunnel.access === "public" ? `<span class="pill warn">${ICON.globe} public</span>` : `<span class="pill lock">${ICON.lock} login</span>`));
  else if (d.tunnel) out.push('<div class="dl-row"><span class="dl-k">Tunnel</span><span class="faint mono">getting an address…</span></div>');
  if (d.forgeTunnel) out.push(row("Forge link", d.forgeTunnel));
  if (d.localUrl) out.push(row("Local", d.localUrl));
  return out.join("") || '<div class="dl-row"><span class="faint">No links while it is stopped.</span></div>';
}

function deskCard(d) {
  const st = d.running ? `<span class="pill ok"><i class="dot ok"></i>running</span>` : `<span class="pill">${h(d.status)}</span>`;
  return `<article class="card desk${d.running ? "" : " off"}">
    <div class="t-top">
      <div class="fav distro" title="${h(distroLabel(d.family))}">${d.family ? distroLogo(d.family) : ICON.desk}</div>
      <div class="grow"><div class="t-name">${h(d.title)}</div><div class="t-url"><span class="mono">${h(d.name)}</span></div></div>
      ${st}
    </div>
    <div class="t-meta">${d.family ? `<span class="pill">${h(distroLabel(d.family))}</span>` : ""}${d.de ? `<span class="pill">${h(d.de)}</span>` : ""}${d.port ? `<span class="pill">:${d.port}</span>` : ""}${d.tunnel ? `<span class="pill ok">${ICON.lock} via Aegis</span>` : ""}</div>
    <div class="dl">${deskLinks(d)}</div>
    <div class="t-actions">
      ${d.running
        ? `<button class="btn sm" data-act="desk" data-do="stop" data-name="${h(d.name)}">${ICON.stop} Stop</button>
           <button class="btn sm ghost" data-act="desk" data-do="restart" data-name="${h(d.name)}">${ICON.restart} Restart</button>`
        : `<button class="btn sm" data-act="desk" data-do="start" data-name="${h(d.name)}">${ICON.play} Start</button>`}
      <span class="grow"></span>
      ${d.tunnel ? `<button class="btn sm ghost" data-act="open" data-port="${d.tunnel.port}">Traffic</button>
                    <button class="btn sm ghost danger" data-act="unpublish" data-port="${d.tunnel.port}" data-title="${h(d.title)}">Unpublish</button>`
        : d.port ? `<button class="btn sm primary" data-act="publish" data-port="${d.port}" data-title="${h(d.title)}">${ICON.tunnel} Publish</button>` : ""}
    </div>
  </article>`;
}

function renderInteg() {
  const d = S.integData;
  const i = (d && d.integration) || S.integrations.find((x) => x.id === S.integ);
  if (!i) { app.innerHTML = '<p class="muted">Loading…</p>'; return; }
  const desks = d ? d.desktops : [];
  app.innerHTML = `
    <button class="back" data-act="home">${ICON.back} Burrow</button>
    <section class="card lit d-head">
      <div class="integ-logo lg">${i.logo ? `<img src="${h(i.logo)}" alt="">` : h(i.name[0])}</div>
      <div class="grow">
        <h1>${h(i.name)}</h1>
        <div class="t-meta" style="margin-top:8px">${d ? (d.reachable ? `<span class="pill ok"><i class="dot ok"></i>connected</span>` : `<span class="pill err" title="${h(d.error)}"><i class="dot err"></i>not answering</span>`) : '<span class="pill">checking</span>'}
          ${i.version ? `<span class="pill">v${h(i.version)}</span>` : ""}<span class="pill">${desks.length} desktop${desks.length === 1 ? "" : "s"}</span>${d && d.running ? `<span class="pill">${d.running} running</span>` : ""}</div>
      </div>
      <a class="btn primary" href="${h(i.dashboard)}" target="_blank" rel="noopener">${ICON.ext} Open ${h(i.name)} dashboard</a>
    </section>
    ${d && !d.reachable ? `<div class="card panel note-err"><b>${h(i.name)} is not answering.</b> <span class="muted">${h(d.error)}. Is its web UI running?</span></div>` : ""}
    ${desks.length ? `<div class="grid">${desks.map(deskCard).join("")}</div>` : d && d.reachable ? `
      <div class="card lit empty"><div class="big">${ICON.desk}</div><h2>No desktops yet</h2>
        <p>Desktops you create in ${h(i.name)} show up here with their links, and you can publish any of them through Aegis.</p>
        <a class="btn primary" href="${h(i.dashboard)}" target="_blank" rel="noopener">${ICON.ext} Open ${h(i.name)}</a></div>` : ""}`;
}

// ------------------------------------------------------------------ addon
// Burrow → Addon: Aegis × Burrow as a Selkies Forge addon. What the Forge
// installed (version, commit, linked or fresh), whether an update waits, what
// it can run (scripts, actions, settings), and what it did through Burrow's
// control socket. All of it comes from GET /__gate/api/addon.
const REPO = "https://github.com/alexd-aero/aegis-burrow";
const short = (c) => String(c || "").slice(0, 7);
function addonHero(a) {
  const f = a.forge, ad = a.addon, man = a.manifest;
  const linked = !!ad, upd = linked && ad.update && ad.update.available;
  const forgeLogo = f && f.logo ? f.logo : "/__gate/logos/forge.svg";
  const wire = `<div class="ab-link" aria-hidden="true">
      <div class="ab-node"><img src="/__gate/logos/aegis-burrow.svg" alt=""><b>Aegis × Burrow</b><small class="mono">v${h(man.version || "")}</small></div>
      <div class="ab-wire"><span class="ab-line"><i></i></span><em>${linked ? "addon" : f ? "ready to link" : "no forge"}</em></div>
      <div class="ab-node${f ? "" : " ghost"}"><img src="${h(forgeLogo)}" alt=""><b>Selkies Forge</b><small class="mono">${f && f.version ? "v" + h(f.version) : "–"}</small></div>
    </div>`;
  if (!linked && f) {
    // Not linked yet: Burrow offers to do it (after asking), or shows the way by hand.
    return `<section class="card lit ab-hero ask">
    ${wire}
    <div class="ab-copy">
      <h1>Add Aegis × Burrow to Selkies Forge?</h1>
      <p>Selkies Forge ${h(f.version)} is on this machine. As one of its addons, Aegis × Burrow gets updated, restarted and checked on from the Forge, and Burrow gets the Forge's desktops. Burrow can add itself for you, or you can do it by hand.</p>
      <div class="ab-choices" role="group" aria-label="How to add it">
        <button class="ab-choice primary" data-act="bridge-ask"${S.bridgeBusy ? " disabled" : ""}>
          <span class="ab-choice-i">${S.bridgeBusy ? '<span class="spin"></span>' : ICON.plug}</span>
          <span><b>${S.bridgeBusy ? "Adding…" : "Add it for me"}</b><small>Burrow asks first, then has the Forge add and link it. About a minute.</small></span></button>
        <button class="ab-choice${S.manual ? " on" : ""}" data-act="bridge-manual">
          <span class="ab-choice-i">${ICON.term}</span>
          <span><b>I'll do it myself</b><small>The link to paste and the button to press, on the Forge's own Addons page.</small></span></button>
      </div>
    </div>
  </section>`;
  }
  const title = linked ? "Connected to Selkies Forge, as an addon" : "Not an addon yet";
  const text = linked
    ? `Selkies Forge ${ad.adopted ? "linked the copy that was already on this machine" : "installed it"}${ad.installedAt ? ` ${ago(ad.installedAt * 1000)}` : ""}. It updates, restarts and checks on it from its Addons page, and publishes desktops through Burrow.`
    : `Install Selkies Forge (150+ Linux desktops in the browser): Burrow sees it within a minute and offers to link the two. Its desktops get a card here, and Burrow publishes them.`;
  return `<section class="card lit ab-hero${linked ? " on" : ""}${upd ? " upd" : ""}">
    ${wire}
    <div class="ab-copy">
      <h1>${linked ? `<span class="ab-ok">${ICON.check}</span>` : ""}${h(title)}</h1>
      <p>${text}</p>
      ${linked ? `<div class="t-meta"><span class="pill mono">${h(ad.id)}</span><span class="pill mono">v${h(ad.version)}</span>${ad.commit ? `<span class="pill mono" title="${h(ad.commit)}">${h(short(ad.commit))}</span>` : ""}
        <span class="pill">${ad.adopted ? "linked" : "installed by the Forge"}</span>${ad.state ? `<span class="pill ${ad.state === "running" ? "ok" : ""}"><i class="dot ${ad.state === "running" ? "ok" : "idle"}"></i>${h(ad.state)}</span>` : ""}</div>` : ""}
      <div class="row ab-btns">
        ${linked && ad.page ? `<a class="btn primary" href="${h(ad.page)}" target="_blank" rel="noopener">${ICON.ext} Open in Selkies Forge</a>`
          : `<a class="btn primary" href="https://github.com/adatskov-wcpss/animated-fiesta" target="_blank" rel="noopener">${ICON.ext} Get Selkies Forge</a>`}
        ${f ? `<button class="btn" data-act="integ" data-id="${h(f.id)}">${ICON.desk} Its desktops</button>` : ""}
      </div>
    </div>
  </section>`;
}
function addonSteps(a) {
  const f = a.forge;
  const step = (n, body) => `<li><span class="ab-n">${n}</span><div>${body}</div></li>`;
  return `<section class="card panel ab-steps"><h3>${f ? "Adding it by hand" : "Make it an addon"} <span class="faint">${f ? "two steps" : "three steps"}</span></h3><ol>
    ${f ? "" : step(1, `Install Selkies Forge on this machine:<div class="ab-code mono">curl -fsSL https://raw.githubusercontent.com/adatskov-wcpss/animated-fiesta/main/docker.sh | bash<button class="copy" data-act="copy" data-text="curl -fsSL https://raw.githubusercontent.com/adatskov-wcpss/animated-fiesta/main/docker.sh | bash" aria-label="Copy">${ICON.copy}</button></div>`)}
    ${step(f ? 1 : 2, `${f ? `<a class="link" href="${h(f.dashboard.replace(/#.*$/, ""))}#addons" target="_blank" rel="noopener">Open Selkies Forge's Addons page</a>` : "In Selkies Forge, open <b>Addons</b>"} and paste:<div class="ab-code mono">${REPO}<button class="copy" data-act="copy" data-text="${REPO}" aria-label="Copy">${ICON.copy}</button></div>Or find <b>Aegis × Burrow</b> under <i>Found on this machine</i> there.`)}
    ${step(f ? 2 : 3, `Press <b>Link it</b> (or <b>Add and link</b>). It is already on this machine, so the Forge links it and keeps your login, domain and tunnels. Burrow then adds the Forge back, and this tab lights up within a minute.`)}
  </ol></section>`;
}
// ------------------------------------------------------------------ the bridge's health
function loadBridge(force) {
  if (force) { S.bridge = null; render(); }
  return api("/__gate/api/bridge").then((b) => { S.bridge = b; render(); }).catch(() => {});
}
function bridgePanel() {
  const b = S.bridge;
  if (!b) return `<section class="card panel bridge-panel"><h3>${ICON.shield} Bridge health <span class="faint">checking…</span></h3><div class="skel-row"></div></section>`;
  const word = { ok: "up and private", warn: "up, with something to look at", fail: "needs attention", off: "no Selkies Forge yet" }[b.state];
  const n = b.checks.filter((c) => c.state === "ok").length;
  const row = (c) => `<li class="bc ${c.state}"><span class="bc-i">${{ ok: ICON.check, warn: "!", fail: "✕", off: "–" }[c.state]}</span>
      <div class="grow"><b>${h(c.label)}</b><div class="muted small">${h(c.detail)}</div></div>
      ${c.fix === "connect" && !S.bridgeBusy ? `<button class="btn sm" data-act="bridge-ask">${ICON.plug} Add it</button>` : ""}</li>`;
  const fs = b.forgeSide;
  return `<section class="card panel bridge-panel ${b.state}">
    <h3>${ICON.shield} Bridge health <span class="pill ${b.state === "ok" ? "ok" : b.state === "fail" ? "err" : b.state === "warn" ? "warn" : ""}">${h(word)}</span>
      <span class="faint">${n}/${b.checks.length} pass · ${ago(b.checked)}</span><span class="grow"></span>
      <button class="btn sm ghost" data-act="bridge-check">${ICON.restart} Check again</button></h3>
    <div class="bridge-cols">
      <div><div class="bridge-side">${ICON.shield} Seen from Burrow</div><ul class="bc-list">${b.checks.map(row).join("")}</ul></div>
      ${fs ? `<div><div class="bridge-side"><img src="/__gate/logos/forge.svg" alt=""> Seen from Selkies Forge <span class="pill ${fs.state === "ok" ? "ok" : fs.state === "fail" ? "err" : "warn"}">${h(fs.state || "?")}</span></div>
        <ul class="bc-list">${fs.checks.map(row).join("")}</ul></div>` : ""}
    </div>
  </section>`;
}
// "Add it for me": say exactly what will happen, and only go on with a yes.
function bridgeAsk() {
  const f = S.addon && S.addon.forge;
  if (!f) return;
  const li = (t) => `<li>${t}</li>`;
  openModal(`<h2>Let Burrow add itself to Selkies Forge?</h2>
    <p>Nothing happens until you allow it. This is what Burrow will do:</p>
    <ol class="perm">
      ${li(`<b>Check its own <span class="mono">forge-addon.json</span></b> with the Forge's rules. Nothing leaves this machine.`)}
      ${li(`<b>Ask the Forge</b> at <span class="mono">${h(f.local.replace(/^https?:\/\//, "").replace(/\/$/, ""))}</span> to add <span class="mono">${h(REPO.replace("https://", ""))}</span> (or this machine's copy, if GitHub can't be reached).`)}
      ${li(`<b>The Forge links the copy that is already here.</b> It runs Aegis × Burrow's install script, which keeps your login, domain, tunnels and settings. Aegis restarts for a few seconds, so this page may blink.`)}
      ${li(`<b>Add Selkies Forge as a Burrow addon</b>, from its own checkout, so each shows the other.`)}
    </ol>
    <p class="faint small">To undo it later: the Forge's Addons page → Aegis × Burrow → ⋯ → Uninstall, then Remove (your gate keeps running).</p>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="permGo">${ICON.plug} Allow and add</button></div>`, (m) => {
    m.querySelector("#permGo").addEventListener("click", () => { closeModal(); bridgeConnect(); });
  });
}
async function bridgeConnect() {
  S.bridgeBusy = true; render();
  let r;
  try { r = await api("/__gate/api/bridge/connect", { method: "POST", body: "{}" }); }
  catch (e) { S.bridgeBusy = false; render(); openModal(`<h2>Could not add it</h2><p class="err-msg">${h(e.message)}</p><p class="muted small">Nothing was changed. You can still add it by hand.</p><div class="modal-actions"><button class="btn primary" data-act="close">Close</button></div>`); return; }
  if (r.local && r.local.error) toast(r.local.error);
  if (!r.forge || r.forge.already || !r.forge.job) { S.bridgeBusy = false; toast("It is already an addon of Selkies Forge"); S.addon = null; loadBridge(true); refresh(); return; }
  // follow the Forge's job: its phase, its log, and Aegis's own restart in the middle
  const jid = r.forge.job.id || r.forge.job;
  let since = 0, misses = 0;
  openModal(`<h2>Adding Aegis × Burrow to Selkies Forge</h2><p id="jobP" class="mono small">asking the Forge…</p>
    <div class="jbar"><i id="jobB" style="width:4%"></i></div><pre class="jlog" id="jobL"></pre>
    <div class="modal-actions" id="jobA"><span class="faint small">Aegis restarts for a moment near the end; this keeps going.</span></div>`);
  S.modal.querySelector(".modal").classList.add("wide");
  const tick = async () => {
    if (!S.modal) { S.bridgeBusy = false; return; }
    try {
      const v = await api(`/__gate/api/bridge/job/${encodeURIComponent(jid)}?since=${since}`);
      misses = 0; since = v.next;
      const L = S.modal.querySelector("#jobL");
      for (const l of v.lines) { const d = document.createElement("div"); d.textContent = l.line; if (l.cls) d.className = l.cls; L.append(d); }
      L.scrollTop = L.scrollHeight;
      S.modal.querySelector("#jobP").textContent = v.state === "running" ? v.phase || "working" : v.state === "done" ? "Linked." : v.error || v.state;
      S.modal.querySelector("#jobB").style.width = Math.round((v.state === "running" ? Math.max(0.04, v.progress) : 1) * 100) + "%";
      if (v.state !== "running") {
        S.bridgeBusy = false;
        S.modal.querySelector(".jbar").classList.add(v.state === "done" ? "ok" : "bad");
        S.modal.querySelector("#jobA").innerHTML = `${v.state === "done" ? `<a class="btn" href="${h(v.page)}" target="_blank" rel="noopener">${ICON.ext} Open in Selkies Forge</a>` : ""}<button class="btn primary" data-act="close">${v.state === "done" ? "Done" : "Close"}</button>`;
        S.addon = null; setTimeout(() => { loadBridge(true); refresh(); }, 1500);
        return;
      }
    } catch { if (++misses > 90) { S.bridgeBusy = false; S.modal.querySelector("#jobP").textContent = "Lost track of it; check the Forge's Addons page."; return; } }
    setTimeout(tick, 1000);
  };
  tick();
}

// ------------------------------------------------------------------ Burrow's addons
// The same addons as Selkies Forge's (one format, read by both). Paste a
// link, or pick from what the scan found on this machine.
const PLAT = { "selkies-forge": "Selkies Forge", burrow: "Burrow" };
function loadScan(fresh) {
  S.scanning = true; if (S.view === "addons") render();
  return api(`/__gate/api/addons/scan${fresh ? "?fresh=1" : ""}`).then((r) => { S.scan = r; })
    .catch((e) => { S.scan = { error: e.message, addons: [], scanned: Date.now() }; })
    .finally(() => { S.scanning = false; if (S.view === "addons") render(); });
}
function adState(a) {
  const st = a.status || {};
  if (a.busy) return `<span class="pill"><span class="spin sm"></span>${h(a.busy.phase || "working")}</span>`;
  if (!a.installed) return a.detected && a.detected.found ? '<span class="pill warn"><i class="dot warn"></i>on this machine</span>' : '<span class="pill">not installed</span>';
  if (st.state === "running") return '<span class="pill ok"><i class="dot ok"></i>running</span>';
  if (st.state === "stopped") return '<span class="pill err"><i class="dot err"></i>stopped</span>';
  if (st.state === "error") return `<span class="pill err" title="${h(st.detail || "")}"><i class="dot err"></i>error</span>`;
  return '<span class="pill ok"><i class="dot ok"></i>installed</span>';
}
const shortSrc = (s) => String(s || "").replace(/^https:\/\/(www\.)?(github\.com\/)?/, "").replace(/^\/home\/[^/]+/, "~");
// "is made for Burrow, not …" is about the addon; the rest are about this machine
const problemText = (ps) => ps.map((p) => (/^is made for/.test(p) ? "It " : "This machine ") + p).join(". ") + ".";
function adCard(a) {
  const upd = a.installed && a.remote && a.remote.up_to_date === false;
  const w = a.ways;
  return `<article class="card lit adc${a.installed ? " on" : ""}${upd ? " upd" : ""}">
    <div class="t-top">
      <div class="fav lg">${a.logo ? `<img src="${h(a.logo)}" alt="">` : h(a.name[0])}</div>
      <div class="grow" style="min-width:0"><div class="t-name">${h(a.name)} <span class="faint mono small">v${h(a.installed && a.installed_version ? a.installed_version : a.version)}</span>${upd ? ' <span class="newchip">update</span>' : ""}</div>
        <div class="t-url"><span class="mono faint small" title="${h(a.source)}">${h(shortSrc(a.source))}</span></div></div>
      ${adState(a)}
    </div>
    <p class="adc-desc">${h(a.description || "No description.")}</p>
    ${a.problems.length ? `<div class="note-err small">${h(problemText(a.problems))}</div>` : ""}
    ${a.installed && w ? `<div class="dl">${w.burrow && w.burrow.url ? `<div class="dl-row"><span class="dl-k">Burrow</span><a class="mono" href="${h(w.burrow.url)}" target="_blank" rel="noopener">${h(w.burrow.url.replace(/^https:\/\//, ""))}</a></div>` : ""}
      <div class="dl-row"><span class="dl-k">Local</span><span class="mono">${h(w.local)}</span></div></div>` : ""}
    <div class="t-actions">
      ${!a.installed ? `<button class="btn sm primary" data-act="ad-install" data-id="${h(a.id)}"${a.busy || a.problems.length ? " disabled" : ""}>${a.detected && a.detected.found ? "Link it" : "Install"}</button>`
        : a.open_url ? `<a class="btn sm primary" href="${h(a.open_url)}" target="_blank" rel="noopener">${ICON.ext} Open</a>` : ""}
      ${a.installed && w ? (w.burrow ? `<button class="btn sm ghost" data-act="ad-share" data-on="0" data-id="${h(a.id)}">Unpublish</button>`
        : `<button class="btn sm" data-act="ad-share" data-on="1" data-id="${h(a.id)}">${ICON.tunnel} Publish</button>`) : ""}
      ${upd ? `<button class="btn sm ok" data-act="ad-update" data-id="${h(a.id)}">${ICON.up} Update</button>` : ""}
      <span class="grow"></span>
      <details class="more"><summary class="btn sm ghost icon" aria-label="More">⋯</summary><div class="more-menu">
        ${a.installed ? a.actions.map((x) => `<button data-act="ad-action" data-id="${h(a.id)}" data-action="${h(x.id)}" data-confirm="${h(x.confirm || "")}">${h(x.label)}</button>`).join("") : ""}
        <button data-act="ad-check" data-id="${h(a.id)}">Check for updates</button>
        ${a.settings.length ? `<button data-act="ad-install" data-id="${h(a.id)}">Settings and reinstall</button>` : ""}
        ${a.links.map((l) => `<a href="${h(l.url)}" target="_blank" rel="noopener">${h(l.label)}</a>`).join("")}
        ${a.installed ? `<button class="danger" data-act="ad-uninstall" data-id="${h(a.id)}">Uninstall</button>` : `<button class="danger" data-act="ad-remove" data-id="${h(a.id)}">Remove from the list</button>`}
      </div></details>
    </div>
  </article>`;
}
function foundRow(e) {
  const only = !e.compatible ? `<span class="pill">${h(e.platforms.map((p) => PLAT[p] || p).join(" + "))} only</span>` : "";
  const st = e.state === "running" ? '<span class="pill ok"><i class="dot ok"></i>running</span>' : e.state === "stopped" ? '<span class="pill err"><i class="dot err"></i>stopped</span>'
    : e.found ? `<span class="pill warn">installed${e.installed_version ? " " + h(e.installed_version) : ""}</span>` : '<span class="pill">not installed</span>';
  return `<div class="fnd${e.compatible ? "" : " off"}">
    <div class="fav">${e.logo ? `<img src="${h(e.logo)}" alt="">` : h(e.name[0])}</div>
    <div class="grow" style="min-width:0"><div class="fnd-n">${h(e.name)} <span class="faint mono small">v${h(e.version)}</span> ${st} ${only}</div>
      <div class="mono faint small fnd-p" title="${h(e.locations.join("\n"))}">${h(shortSrc(e.source))}${e.locations.length > 1 ? ` · ${e.locations.length} copies` : ""}</div></div>
    ${!e.compatible ? "" : e.problems.length ? `<span class="faint small">${h(e.problems[0])}</span>`
      : `<button class="btn sm${e.found ? " primary" : ""}" data-act="ad-add" data-src="${h(e.source)}">${e.found ? "Add and link" : "Add"}</button>`}
  </div>`;
}
function renderAddons() {
  const list = S.addons, sc = S.scan;
  const found = sc ? sc.addons.filter((e) => !e.registered) : [];
  app.innerHTML = `
    <div class="head"><div><h1>Burrow</h1><p>Addons: apps that install beside Burrow. The same format as Selkies Forge's, so one addon works in both unless it says otherwise.</p></div></div>
    ${subtabs()}
    <section class="card panel addbar">
      <form class="row" id="adForm" autocomplete="off">
        <input class="input grow" id="adSrc" spellcheck="false" placeholder="https://github.com/owner/repo  ·  …/tree/main/a/folder  ·  a GitLab link  ·  https://…/addon.zip" aria-label="Addon repository link">
        <button class="btn primary" id="adGo">Add</button>
      </form>
      <div class="faint small" style="margin-top:8px">Addons run as you on this machine, like anything you install. Powered by the <a class="link" href="https://github.com/alexd-aero/weft" target="_blank" rel="noopener">Weft Architecture</a> · <a class="link" href="https://github.com/alexd-aero/weft#-the-examples" target="_blank" rel="noopener">examples →</a></div>
      <div id="adErr" class="err-msg"></div>
    </section>
    <section class="found">
      <div class="found-head"><h3>Found on this machine</h3><span class="faint small">${S.scanning ? "looking through your folders for forge-addon.json…" : sc ? `${found.length} not added · ${sc.addons.length - found.length} added` : ""}</span>
        <span class="grow"></span><button class="btn sm ghost" data-act="scan"${S.scanning ? " disabled" : ""}>${S.scanning ? '<span class="spin sm"></span>' : ICON.restart} Scan again</button></div>
      ${found.length ? `<div class="found-grid">${found.map(foundRow).join("")}</div>` : S.scanning ? '<div class="skel-row"></div>' : '<p class="faint small" style="margin:0">Nothing new: every addon on this machine is already in the list.</p>'}
    </section>
    ${!list ? '<p class="muted">Loading…</p>' : list.length ? `<div class="grid">${list.map(adCard).join("")}</div>` : `
      <div class="card lit empty"><div class="big">${ICON.box}</div><h2>No addons yet</h2>
        <p>Paste a repository link above, or add one the scan found.</p></div>`}`;
  const form = $("#adForm");
  form.addEventListener("submit", (e) => { e.preventDefault(); addAddon($("#adSrc").value, $("#adGo")); });
}
async function addAddon(src, btn) {
  if (!String(src || "").trim()) return;
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin sm"></span> Fetching…'; }
  try {
    const r = await api("/__gate/api/addons/add", { method: "POST", body: JSON.stringify({ source: src }) });
    toast(`Added ${r.addon.name}`);
    S.scan = null; await refresh();
    if (r.addon.detected && r.addon.detected.found && !r.addon.problems.length) installForm(r.addon.id);
  } catch (e) { const el = $("#adErr"); if (el) el.textContent = e.message; else toast(e.message); }
  finally { if (btn) { btn.disabled = false; btn.textContent = btn.id === "adGo" ? "Add" : "Add"; } }
}
function installForm(id) {
  const a = (S.addons || []).find((x) => x.id === id);
  if (!a) return;
  if (!a.settings.length) return jobRun(id, "install", { settings: {} });
  const field = (s) => {
    const v = s.value == null ? "" : s.value, idf = "set_" + s.key;
    const icon = s.icon ? `<img class="set-ico" src="${h(s.icon)}" alt="">` : "";
    if (s.type === "bool") return `<label class="kv-row set-bool">${icon}<span class="grow"><b>${h(s.label)}</b>${s.help ? `<div class="faint small">${h(s.help)}</div>` : ""}</span>
      <span class="switch"><input type="checkbox" id="${idf}" data-key="${h(s.key)}"${v ? " checked" : ""}><i></i></span></label>`;
    const input = s.type === "select" ? `<select class="input" id="${idf}" data-key="${h(s.key)}">${s.options.map((o) => `<option value="${h(o.value)}"${String(v) === o.value ? " selected" : ""}>${h(o.label)}</option>`).join("")}</select>`
      : `<input class="input" id="${idf}" data-key="${h(s.key)}" type="${s.type === "password" ? "password" : s.type === "number" ? "number" : "text"}" value="${h(v)}">`;
    return `<label class="field"><span>${icon}${h(s.label)}</span>${input}${s.help ? `<small class="faint">${h(s.help)}</small>` : ""}</label>`;
  };
  openModal(`<h2>${a.detected && a.detected.found && !a.installed ? "Link" : a.installed ? "Reinstall" : "Install"} ${h(a.name)}</h2>
    <p>${a.detected && a.detected.found && !a.installed ? "It is already on this machine: Burrow links it and keeps what it has." : "Its install script runs with these settings."}</p>
    <form id="setF">${a.settings.map(field).join("")}<div class="err-msg" id="setErr"></div>
      <div class="modal-actions"><button type="button" class="btn ghost" data-act="close">Cancel</button><button class="btn primary">${a.detected && a.detected.found && !a.installed ? "Link it" : "Install"}</button></div></form>`, (m) => {
    m.querySelector("#setF").addEventListener("submit", (e) => {
      e.preventDefault();
      const settings = {};
      m.querySelectorAll("[data-key]").forEach((el) => { settings[el.dataset.key] = el.type === "checkbox" ? el.checked : el.value; });
      closeModal(); jobRun(id, "install", { settings });
    });
  });
}
function uninstallForm(id) {
  const a = (S.addons || []).find((x) => x.id === id);
  openModal(`<h2>Uninstall ${h(a.name)}?</h2><p>Its uninstall script runs. It stays in the list, so you can install it again.</p>
    <label class="kv-row"><span class="grow"><b>Also delete its data</b><div class="faint small">Logins, settings and anything else it kept. Cannot be undone.</div></span><span class="switch"><input type="checkbox" id="unPurge"><i></i></span></label>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn danger" id="unGo">Uninstall</button></div>`, (m) => {
    m.querySelector("#unGo").addEventListener("click", () => { const purge = m.querySelector("#unPurge").checked; closeModal(); jobRun(id, "uninstall", { keep_data: !purge }); });
  });
}
async function jobRun(id, op, body) {
  let job;
  try { job = (await api(`/__gate/api/addons/${id}/${op}`, { method: "POST", body: JSON.stringify(body || {}) })).job; }
  catch (e) { toast(e.message); return; }
  let since = 0, done = false;
  openModal(`<h2 id="jobT">${h(job.label)}</h2><p id="jobP" class="mono small">${h(job.phase)}</p>
    <div class="jbar"><i id="jobB" style="width:${Math.round(job.progress * 100)}%"></i></div>
    <pre class="jlog" id="jobL"></pre>
    <div class="modal-actions" id="jobA"><button class="btn ghost" data-act="job-cancel" data-job="${job.id}">Cancel</button></div>`);
  S.modal.querySelector(".modal").classList.add("wide");
  const tick = async () => {
    if (!S.modal || done) return;
    try {
      const v = await api(`/__gate/api/addons/jobs/${job.id}?since=${since}`);
      since = v.next;
      const L = S.modal.querySelector("#jobL");
      for (const l of v.lines) { const d = document.createElement("div"); d.textContent = l.line; if (l.cls) d.className = l.cls; L.append(d); }
      L.scrollTop = L.scrollHeight;
      S.modal.querySelector("#jobP").textContent = v.state === "running" ? v.phase : v.state === "done" ? "Done." : v.error || v.state;
      S.modal.querySelector("#jobB").style.width = Math.round((v.state === "running" ? v.progress : 1) * 100) + "%";
      if (v.state !== "running") {
        done = true;
        S.modal.querySelector(".jbar").classList.add(v.state === "done" ? "ok" : "bad");
        const open = v.result && v.result.open_url;
        S.modal.querySelector("#jobA").innerHTML = `${open ? `<a class="btn" href="${h(open)}" target="_blank" rel="noopener">${ICON.ext} Open</a>` : ""}<button class="btn primary" data-act="close">Close</button>`;
        S.scan = null; S.addons = null;
        return;
      }
    } catch { /* Burrow restarting: keep asking */ }
    setTimeout(tick, 700);
  };
  tick();
}
async function checkUpdates(id) {
  const a = (S.addons || []).find((x) => x.id === id);
  openModal(`<h2>${h(a ? a.name : id)}</h2><p>Asking its repository for newer commits…</p><div class="skel-row"></div>`);
  try {
    const r = await api(`/__gate/api/addons/${id}/check`, { method: "POST", body: "{}" });
    const m = S.modal && S.modal.querySelector(".modal");
    if (!m) return;
    m.innerHTML = r.up_to_date === false
      ? `<div class="upd-hero"><span class="ab-up">${ICON.up}</span><div><h2>Commit <span class="mono">${h(r.remote.short)}</span> is available</h2>
          <p class="muted">${r.remote.version && r.remote.version !== r.local.version ? `v${h(r.local.version)} → v${h(r.remote.version)} · ` : ""}${(r.commits || []).length} new commit${(r.commits || []).length === 1 ? "" : "s"}</p></div></div>
        <ul class="upd-list">${(r.commits || []).slice(0, 8).map((c) => `<li><span class="mono faint">${h(c.short)}</span> ${h(c.subject)}</li>`).join("")}</ul>
        <div class="modal-actions"><button class="btn ghost" data-act="close">Later</button><button class="btn ok" data-act="ad-update" data-id="${h(id)}">${ICON.up} Update</button></div>`
      : `<div class="upd-hero"><span class="ab-ok">${ICON.check}</span><div><h2>Up to date</h2><p class="muted">${h(r.note || `Installed at ${r.local.commit ? r.local.commit.slice(0, 7) : "?"}, the newest commit.`)}</p></div></div>
        <div class="modal-actions"><button class="btn primary" data-act="close">Close</button></div>`;
  } catch (e) { if (S.modal) S.modal.querySelector(".modal").innerHTML = `<h2>Could not check</h2><p class="err-msg">${h(e.message)}</p><div class="modal-actions"><button class="btn primary" data-act="close">Close</button></div>`; }
}

function renderAddon() {
  const a = S.addon;
  if (!a) { app.innerHTML = `<div class="head"><div><h1>Burrow</h1><p>Loading…</p></div></div>${subtabs()}`; return; }
  const f = a.forge, ad = a.addon, man = a.manifest, c = a.control || { clients: [], activity: [] };
  if (!f && !ad) {
    // No Forge here: nothing to link, and nothing pushed on anyone.
    app.innerHTML = `<div class="head"><div><h1>Burrow</h1><p>Selkies Forge, and linking it with Aegis × Burrow.</p></div></div>
      ${subtabs()}
      <section class="card panel ab-none"><img src="/__gate/logos/forge.svg" alt="" width="44" height="44">
        <div><h3>Selkies Forge isn't on this machine</h3>
        <p class="muted">That's fine: Aegis × Burrow works on its own, and there is nothing to link. If Selkies Forge is ever installed here, Burrow notices within a minute and this tab offers to connect the two.</p></div></section>`;
    return;
  }
  const upd = ad && ad.update, sum = f ? S.forgeSummary[f.id] : null;
  const forgeClient = c.clients.find((x) => x.id === "selkies-forge");
  const calls = c.clients.reduce((n, x) => n + x.calls, 0);
  const chip = (t, cls = "") => `<span class="ab-chip ${cls}">${t}</span>`;
  const who = (id) => id === "selkies-forge" ? `<img src="${h(f && f.logo ? f.logo : "/__gate/logos/forge.svg")}" alt="">Selkies Forge`
    : id === "cli" ? `<span class="ab-ico">${ICON.term}</span>the burrow CLI` : `<span class="ab-ico">${ICON.plug}</span>${h(id)}`;
  app.innerHTML = `
    <div class="head">
      <div><h1>Burrow</h1><p>The engine under Aegis, and how Selkies Forge runs the two of them as one addon.</p></div>
      <div class="spacer"></div>
      <a class="btn ghost" href="${REPO}#-selkies-forge" target="_blank" rel="noopener">${ICON.ext} How it works</a>
    </div>
    ${subtabs()}
    ${addonHero(a)}
    ${bridgePanel()}
    ${upd && upd.available ? `<div class="card ab-update"><span class="ab-up">${ICON.up}</span><div class="grow">
        <b>Commit <span class="mono">${h(short(upd.commit))}</span> is available${upd.version && upd.version !== ad.version ? ` (v${h(upd.version)})` : ""}</b>
        <div class="muted small">${upd.subject ? h(upd.subject) + " · " : ""}found ${ad.checkedAt ? ago(ad.checkedAt * 1000) : "recently"}. Selkies Forge installs it and keeps everything you set up.</div></div>
        ${ad.page ? `<a class="btn ok" href="${h(ad.page)}" target="_blank" rel="noopener">${ICON.up} Update in Selkies Forge</a>` : ""}</div>` : ""}
    ${ad ? `<div class="stats">
      <div class="card stat"><b>v${h(ad.version)}</b><span>installed by the Forge</span><div class="sub">${ad.commit ? h(short(ad.commit)) + " · " : ""}${ad.installedAt ? ago(ad.installedAt * 1000) : "–"}</div></div>
      <div class="card stat"><b class="${upd && upd.available ? "ab-g" : ""}">${!upd ? "–" : upd.available ? "Update" : "Up to date"}</b><span>updates</span><div class="sub">${ad.checkedAt ? "checked " + ago(ad.checkedAt * 1000) : "not checked yet"}</div></div>
      <div class="card stat"><b>${sum ? (sum.reachable ? sum.desktops : "–") : "…"}</b><span>Forge desktops</span><div class="sub">${sum && sum.reachable ? sum.running + " running" : sum ? "not answering" : "asking"}</div></div>
      <div class="card stat"><b>${fmtN(calls)}</b><span>control socket calls</span><div class="sub">${forgeClient ? "Forge: " + ago(forgeClient.last) : "since Aegis started"}</div></div>
    </div>` : !f || S.manual ? addonSteps(a) : ""}
    <div class="d-two">
      <section class="card panel"><h3>How they're linked</h3>
        <dl class="kv">
          <dt>Addon</dt><dd>${h(man.id || "")} · spec ${h(man.spec || 1)}</dd>
          <dt>Source</dt><dd>${ad && ad.source ? `<a class="link" href="${h(ad.source)}" target="_blank" rel="noopener">${h(ad.source.replace(/^https:\/\//, ""))}</a>` : `<a class="link" href="${REPO}" target="_blank" rel="noopener">${REPO.replace(/^https:\/\//, "")}</a>`}</dd>
          <dt>Selkies Forge</dt><dd>${f ? `<a class="link" href="${h(f.dashboard)}" target="_blank" rel="noopener">${h(f.local.replace(/^https?:\/\//, "").replace(/\/$/, ""))}</a>` : "not on this machine"}</dd>
          <dt>Heartbeat</dt><dd>${f && f.heartbeat ? `<i class="dot ${f.fresh ? "ok" : "warn"}"></i> ${ago(f.heartbeat * 1000)}` : "–"}</dd>
          <dt>Drop-in file</dt><dd>${f ? h(f.dropin) : h((man.integration || "~/.config/aegis/integrations") + "/selkies-forge.json")}</dd>
          <dt>Control socket</dt><dd>${h((c.path || "data/control.sock").replace(/^\/home\/[^/]+/, "~"))} · 600</dd>
          <dt>Burrow</dt><dd>${a.burrow.on ? "on" : "off"} · ${a.burrow.tunnels} tunnel${a.burrow.tunnels === 1 ? "" : "s"} · ${a.burrow.mode === "domain" ? "your domain" : "quick tunnels"}</dd>
        </dl>
      </section>
      <section class="card panel"><h3>What the Forge can run <span class="faint">forge-addon.json</span></h3>
        <div class="ab-group"><span class="ab-k">Lifecycle</span><div>${man.scripts.map((s) => chip(h(s), "mono")).join("")}</div></div>
        <div class="ab-group"><span class="ab-k">Actions</span><div>${man.actions.map((x) => chip(h(x.label))).join("")}</div></div>
        <div class="ab-group"><span class="ab-k">Settings</span><div>${man.settings.map((x) => chip(`<span class="mono">${h(x.key)}</span> ${h(x.label)}`)).join("")}</div></div>
        <p class="faint small" style="margin:12px 0 0">${ad ? "On its card's ⋯ menu in Selkies Forge." : "Once it is an addon, on its card's ⋯ menu in Selkies Forge."}</p>
      </section>
    </div>
    <section class="card panel"><h3>Through the control socket <span class="faint">since Aegis started</span></h3>
      ${c.clients.length ? `<div class="ab-clients">${c.clients.map((x) => `<div class="ab-client"><span class="ab-who">${who(x.id)}</span>
          ${x.version ? `<span class="pill mono">${h(x.version)}</span>` : ""}<span class="grow"></span>
          <span class="faint mono small">${fmtN(x.calls)} call${x.calls === 1 ? "" : "s"} · ${ago(x.last)}</span></div>`).join("")}</div>` : ""}
      ${c.activity.length ? `<ul class="ab-feed">${c.activity.map((e) => `<li><span class="faint mono">${clock(e.at)}</span>
          <span class="ab-who sm">${who(e.client)}</span><span>${h(e.action)}</span>
          ${e.port ? `<span class="pill mono">:${e.port}</span>` : ""}${e.name ? `<span class="muted">${h(e.name)}</span>` : ""}</li>`).join("")}</ul>`
        : `<p class="muted" style="margin:${c.clients.length ? "12px" : "0"} 0 0">No changes yet. When Selkies Forge publishes or unpublishes a desktop through Burrow, it shows up here.</p>`}
    </section>`;
}

function renderDetail() {
  const d = S.detail;
  if (!d) { app.innerHTML = '<p class="muted">Loading…</p>'; return; }
  const tot = d.status["2xx"] + d.status["3xx"] + d.status["4xx"] + d.status["5xx"];
  const pct = (n) => tot ? (n / tot) * 100 : 0;
  const errPct = d.totals.requests ? (d.totals.errors / d.totals.requests) * 100 : 0;
  const lastSec = d.seconds.slice(-10).reduce((a, s) => a + s.req, 0) / 10;
  const blocked = new Set(d.blocked || []);
  app.innerHTML = `
    <button class="back" data-act="home">${ICON.back} All tunnels</button>
    <section class="card lit d-head">
      ${fav(d, true)}
      <div class="grow">
        <h1>${h(displayName(d))}</h1>
        <div class="t-url" style="margin-top:4px"><a href="${h(d.url)}" target="_blank" rel="noopener">${h(d.url)}</a>
          <button class="copy" data-act="copy" data-text="${h(d.url)}" aria-label="Copy link">${ICON.copy}</button></div>
        <div class="t-meta" style="margin-top:10px">${statusPill(d)}${accessPill(d)}${targetPill(d)}</div>
      </div>
      <div class="row" style="flex-wrap:wrap">
        <div class="seg" role="group" aria-label="Who can open it">
          <button data-act="access" data-v="login" class="${d.access === "login" ? "on" : ""}">Login</button>
          <button data-act="access" data-v="password" class="${d.access === "password" ? "on" : ""}">Password</button>
          ${d.kind === "site" ? "" : `<button data-act="access" data-v="public" class="${d.access === "public" ? "on" : ""}">Public</button>`}
        </div>
        ${d.access === "password" ? `<button class="btn sm" data-act="password">${ICON.key} Change password</button>` : ""}
        <label class="switch" title="On/off"><input type="checkbox" data-act="toggle" data-port="${d.port}" ${d.enabled ? "checked" : ""} aria-label="Tunnel on or off"><i></i></label>
        <a class="btn sm" href="${h(d.url)}" target="_blank" rel="noopener">${ICON.ext} Open</a>
        <button class="btn sm" data-act="edit">${ICON.edit} Edit</button>
        <button class="btn sm danger icon" data-act="delete" title="Delete" aria-label="Delete">${ICON.trash}</button>
      </div>
    </section>

    <div class="d-tiles">
      <div class="card stat"><b>${fmtN(d.totals.requests)}</b><span>requests</span><div class="sub">since ${d.first ? ago(d.first) : "–"}</div></div>
      <div class="card stat"><b>${lastSec.toFixed(1)}</b><span>req / s now</span><div class="sub">${fmtN(d.reqPerMin)} / min</div></div>
      <div class="card stat"><b>${fmtN(d.active)}</b><span>open connections</span><div class="sub">${d.wsActive} websocket${d.wsActive === 1 ? "" : "s"}</div></div>
      <div class="card stat"><b>${fmtN(d.online)}<span class="faint">/${fmtN(d.clients)}</span></b><span>clients online</span><div class="sub">${blocked.size} blocked</div></div>
      <div class="card stat"><b>${fmtB(d.totals.bytesOut)}</b><span>served</span><div class="sub">${fmtB(d.totals.bytesIn)} in</div></div>
      <div class="card stat"><b>${fmtMs(d.latency.p50)}</b><span>median latency</span><div class="sub">p95 ${fmtMs(d.latency.p95)} · ${errPct.toFixed(1)}% err</div></div>
    </div>

    <div class="d-two">
      <section class="card panel"><h3>Requests per minute <span class="faint">last 2 h</span></h3>
        ${bars(d.minutes, "req", { errKey: "err" })}
        <div class="legend"><span><i style="background:#d7dade"></i>requests</span><span><i style="background:#ff5a52"></i>errors</span></div></section>
      <section class="card panel"><h3>Live <span class="faint">last 60 s</span></h3>
        ${bars(d.seconds, "req", { hgt: 110, w: 360 })}
        <h3 style="margin-top:16px">Responses</h3>
        <div class="bar" title="status codes">
          <span style="width:${pct(d.status["2xx"])}%;background:#3ddc97"></span><span style="width:${pct(d.status["3xx"])}%;background:#7aa7ff"></span>
          <span style="width:${pct(d.status["4xx"])}%;background:#f2c14e"></span><span style="width:${pct(d.status["5xx"])}%;background:#ff5a52"></span>
        </div>
        <div class="legend"><span class="s2">2xx ${fmtN(d.status["2xx"])}</span><span class="s3">3xx ${fmtN(d.status["3xx"])}</span><span class="s4">4xx ${fmtN(d.status["4xx"])}</span><span class="s5">5xx ${fmtN(d.status["5xx"])}</span></div>
      </section>
    </div>

    <div class="d-two">
      <section class="card panel"><h3>Bandwidth per minute <span class="faint">last 2 h</span></h3>
        ${lines(d.minutes, ["outB", "inB"], ["#e8eaed", "#7aa7ff"])}
        <div class="legend"><span><i style="background:#e8eaed"></i>served</span><span><i style="background:#7aa7ff"></i>received</span></div></section>
      <section class="card panel"><h3>Target</h3>
        <dl class="kv">
          <dt>${d.kind === "site" ? "Serves" : "Address"}</dt><dd>${d.kind === "site" ? `<a class="link" href="${h(d.target)}" target="_blank" rel="noopener">${h(d.target)}</a>` : h(d.target)}</dd>
          <dt>Who</dt><dd>${d.access === "public" ? "anyone with the link" : d.access === "password" ? `its own password${d.lockSet ? ` (set ${ago(d.lockSet)})` : ""}, or your login` : "your Aegis login"}</dd>
          <dt>Health</dt><dd>${d.health.up === null ? "checking" : d.health.up ? `up · ${fmtMs(d.health.ms)}` : "down"}${d.healthSince ? ` · since ${ago(d.healthSince)}` : ""}</dd>
          <dt>Checked</dt><dd>${ago(d.health.checked)}</dd>
          <dt>Host header</dt><dd>${d.kind === "site" ? "the site's own; nothing about visitors is passed on" : d.preserveHost ? "kept (tunnel name)" : "rewritten to target"}</dd>
          <dt>DNS</dt><dd>${d.dns && d.dns.ok ? "proxied CNAME" : h(d.dns && d.dns.error || "pending")}</dd>
          <dt>Created</dt><dd>${new Date(d.created).toLocaleString()}</dd>
          <dt>WebSockets</dt><dd>${fmtN(d.totals.ws)} total</dd>
        </dl>
        <div class="row" style="margin-top:14px;justify-content:flex-end"><button class="btn sm ghost" data-act="reset">Reset stats</button></div>
      </section>
    </div>

    <section class="card panel" style="margin-bottom:14px"><h3>Clients <span class="faint">${fmtN(d.clients)} seen</span></h3>
      ${d.clientList.length ? `<div class="scroll"><table>
        <thead><tr><th></th><th>Client</th><th>Browser</th><th>Requests</th><th>Served</th><th>Open</th><th>First seen</th><th>Last seen</th><th></th></tr></thead>
        <tbody>${d.clientList.map((c) => `<tr>
          <td><i class="dot ${c.active ? "ok" : Date.now() - c.last < 120000 ? "warn" : "idle"}"></i></td>
          <td class="mono">${flag(c.country)} ${h(c.ip)}${c.country ? ` <span class="faint">${h(c.country)}</span>` : ""}</td>
          <td>${h(c.agent || "–")}</td><td class="mono">${fmtN(c.requests)}</td><td class="mono">${fmtB(c.bytesOut)}</td>
          <td class="mono">${c.active || ""}</td><td class="faint">${ago(c.first)}</td><td>${ago(c.last)}</td>
          <td style="text-align:right">${c.active ? `<button class="btn sm ghost" data-act="kick" data-ip="${h(c.ip)}">Kick</button>` : ""}
            ${blocked.has(c.ip) ? `<button class="btn sm" data-act="unblock" data-ip="${h(c.ip)}">Unblock</button>` : `<button class="btn sm ghost danger" data-act="block" data-ip="${h(c.ip)}">Block</button>`}</td>
        </tr>`).join("")}</tbody></table></div>` : '<p class="muted" style="margin:0">Nobody has used this tunnel yet.</p>'}
      ${[...blocked].filter((ip) => !d.clientList.some((c) => c.ip === ip)).map((ip) => `<div class="row" style="margin-top:10px"><span class="pill err">blocked</span><span class="mono">${h(ip)}</span><button class="btn sm" data-act="unblock" data-ip="${h(ip)}">Unblock</button></div>`).join("")}
    </section>

    <section class="card panel"><h3>Recent requests <span class="faint">newest first</span></h3>
      ${d.recent.length ? `<div class="scroll"><table>
        <thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Time</th><th>Size</th><th>Client</th></tr></thead>
        <tbody>${d.recent.map((r) => `<tr>
          <td class="faint mono">${clock(r.t)}</td><td class="mono">${h(r.method)}</td><td class="mono path" title="${h(r.path)}">${h(r.path)}</td>
          <td class="mono s${String(r.status || 5)[0]}">${r.status || h(r.error || "–")}</td><td class="mono">${fmtMs(r.ms)}</td>
          <td class="mono">${fmtB(r.bytes)}</td><td class="mono">${flag(r.country)} ${h(r.ip)}</td></tr>`).join("")}</tbody></table></div>`
        : '<p class="muted" style="margin:0">No requests yet. Open the link to see them arrive here live.</p>'}
    </section>`;
}

function render() {
  if (S.modal) return;          // never repaint under an open form
  if (S.view === "detail") renderDetail(); else if (S.view === "integ") renderInteg(); else if (S.view === "forge") renderAddon();
  else if (S.view === "addons") renderAddons(); else { renderList(); wirePanels(); }
  const to = S.scrollTo && document.getElementById(S.scrollTo);
  if (to) { S.scrollTo = null; to.scrollIntoView({ block: "center" }); to.classList.remove("flash"); void to.offsetWidth; to.classList.add("flash"); }
}

// ------------------------------------------------------------------ data
async function refresh() {
  if (S.busy || document.hidden) return;
  S.busy = true;
  try {
    if (S.view === "detail") S.detail = await api(`/__gate/api/tunnels/${S.port}`);
    else if (S.view === "integ") S.integData = await api(`/__gate/api/integrations/${encodeURIComponent(S.integ)}/desktops`);
    else if (S.view === "addons") {
      S.addons = (await api("/__gate/api/addons")).addons;
      if (!S.scan && !S.scanning) loadScan(false);
    } else if (S.view === "forge") {
      S.addon = await api("/__gate/api/addon");
      if (!S.bridge || Date.now() - S.bridge.checked > 30000) loadBridge();
      const f = S.addon.forge, last = f && S.forgeSummary[f.id];
      if (f && !(last && Date.now() - last.at < 15000)) {
        api(`/__gate/api/integrations/${encodeURIComponent(f.id)}/desktops`).then((d) => {
          S.forgeSummary[f.id] = { at: Date.now(), reachable: d.reachable, desktops: d.desktops.length, running: d.running || 0 };
          if (S.view === "forge") render();
        }).catch(() => {});
      }
    } else {
      const r = await api("/__gate/api/tunnels").catch((e) => { if (/switched off/.test(e.message)) return { off: true, tunnels: [] }; throw e; });
      S.off = !!r.off;
      S.list = r.tunnels; S.mode = r.mode; S.pattern = r.pattern;
      S.integrations = (await api("/__gate/api/integrations")).integrations;
      if (!S.addon || Date.now() - (S.addonAt || 0) > 30000) {       // for the tab's dot
        S.addonAt = Date.now();
        api("/__gate/api/addon").then((a) => { S.addon = a; if (S.view === "list") render(); }).catch(() => {});
      }
      for (const i of S.integrations.filter((x) => x.full)) {
        const last = S.forgeSummary[i.id];
        if (last && Date.now() - last.at < 15000) continue;
        api(`/__gate/api/integrations/${encodeURIComponent(i.id)}/desktops`).then((d) => {
          S.forgeSummary[i.id] = { at: Date.now(), reachable: d.reachable, desktops: d.desktops.length, running: d.running || 0 };
          if (S.view === "list") render();
        }).catch(() => {});
      }
    }
    S.lastOk = Date.now();
    setLive(true, "live");
    render();
  } catch (e) {
    setLive(false, e.message === "No such tunnel." ? "gone" : "offline");
    if (e.message === "No such tunnel.") go("list");
  } finally { S.busy = false; }
}
function schedule() {
  clearInterval(S.timer);
  S.timer = setInterval(refresh, S.view === "detail" ? 2000 : S.view === "forge" || S.view === "addons" ? 5000 : 3000);
}
function go(view, port) {
  S.view = view; S.detail = null;
  if (view === "integ") { S.integ = port; S.integData = null; S.port = null; } else S.port = port || null;
  const want = view === "detail" ? `#/t/${port}` : view === "integ" ? `#/i/${encodeURIComponent(port)}` : view === "forge" ? "#/forge" : view === "addons" ? "#/addons" : "#/";
  if (location.hash !== want) history.pushState(null, "", want);
  render(); refresh(); schedule();
  window.scrollTo(0, 0);
}
function fromHash() {
  if (location.hash === "#/pages") { S.scrollTo = "pagesCard"; history.replaceState(null, "", "#/"); }
  const m = /^#\/t\/(\d+)/.exec(location.hash);
  const i = /^#\/i\/([a-z0-9-]+)/.exec(location.hash);
  if (m) go("detail", Number(m[1])); else if (i) go("integ", i[1]); else if (/^#\/(forge|addon)$/.test(location.hash)) go("forge");
  else if (location.hash === "#/addons") go("addons"); else go("list");
}

// ------------------------------------------------------------------ modals
function closeModal() { S.modal?.remove(); S.modal = null; render(); }
function openModal(html, onReady) {
  closeModal();
  const scrim = document.createElement("div");
  scrim.className = "scrim";
  scrim.innerHTML = `<div class="card lit modal" role="dialog" aria-modal="true">${html}</div>`;
  scrim.addEventListener("mousedown", (e) => { if (e.target === scrim) closeModal(); });
  document.body.append(scrim);
  S.modal = scrim;
  onReady?.(scrim);
}

// "tunnel-PORT-aegis.example.com" -> "example.com" and "tunnel-3000-aegis"
const zoneName = () => S.mode === "domain" && S.pattern ? S.pattern.split(".").slice(1).join(".") : "";
const defaultLabel = (port) => (S.pattern.split(".")[0] || "tunnel-PORT").replace("PORT", port || "PORT");
function previewText(port, sub) {
  if (S.mode !== "domain") return `a random <b>https://….trycloudflare.com</b> address${sub ? `, then <b>https://${h(sub)}.your-domain</b> once a domain is linked` : ""}`;
  if (sub) return `https://<b>${h(sub)}</b>.${h(zoneName())}`;
  const rest = S.pattern.replace(/^tunnel-PORT/, "");
  return `https://<b>tunnel-${h(port)}</b>${h(rest)}`;
}

// Who can open it: the Aegis login (the default), a password of its own, or anyone.
const ACCESS = [["login", "Aegis login"], ["password", "Own password"], ["public", "Public"]];
const accessSeg = (id, cur, site) => `<div class="seg" id="${id}">${ACCESS.filter(([v]) => !(site && v === "public"))
  .map(([v, l]) => `<button type="button" data-v="${v}" class="${cur === v ? "on" : ""}">${l}</button>`).join("")}</div>`;
const pwFields = (locked) => `<div class="pw-box" id="fPwBox">
    <div class="row flexwrap">
      <label class="field grow"><span>Password <span class="faint">(8+ characters${locked ? "; empty keeps the current one" : ""})</span></span><input class="input" id="fPw" type="password" autocomplete="new-password" placeholder="${locked ? "unchanged" : ""}"></label>
      <label class="field grow"><span>Repeat it</span><input class="input" id="fPw2" type="password" autocomplete="new-password"></label>
    </div>
    <p class="faint small pw-note">${ICON.key} Whoever has it gets in; your Aegis login works too. Sealed with ML-KEM-768 + X25519 on its way, kept only as a scrypt hash.</p>
  </div>`;
// the password fields -> {sealedPassword} (or {} to keep it), or throws with what's wrong
async function sealedPw(m, needed) {
  const pw = m.querySelector("#fPw").value, pw2 = m.querySelector("#fPw2").value;
  if (!pw && !needed) return {};
  if (pw.length < 8) throw new Error("Use at least 8 characters for the password.");
  if (pw !== pw2) throw new Error("The two passwords differ.");
  if (!window.AegisSeal) throw new Error("The sealing script didn't load. Reload the page.");
  return { sealedPassword: await window.AegisSeal({ password: pw }) };
}
// what people paste -> what Burrow will serve (the server has the last word)
function siteGuess(v) {
  v = String(v || "").trim().replace(/^https?:\/\//i, "").replace(/^www\./i, "");
  let m = /^(github|gitlab)\.com\/([^/]+)(?:\/(.*))?$/i.exec(v);
  if (m) {
    const host = `${m[2].toLowerCase()}.${m[1].toLowerCase()}.io`;
    let rest = (m[3] || "").split(m[1].toLowerCase() === "github" ? /\/(?:tree|blob)\// : /\/-\//)[0].replace(/\.git$/i, "").replace(/\/+$/, "");
    if (m[1].toLowerCase() === "github") rest = rest.split("/")[0];
    return { provider: m[1].toLowerCase(), url: `${host}/${rest && rest.toLowerCase() !== host ? rest + "/" : ""}` };
  }
  m = /^([a-z0-9-]+\.(github|gitlab)\.io)(\/.*)?$/i.exec(v);
  if (m) return { provider: m[2].toLowerCase(), url: `${m[1].toLowerCase()}${(m[3] || "/").replace(/\/*$/, "/")}` };
  return null;
}
const PROVIDER = { github: "GitHub Pages", gitlab: "GitLab Pages" };

async function tunnelForm(edit, preset, opts = {}) {
  const t = edit || { access: "login", targetHost: "127.0.0.1", scheme: "auto", preserveHost: false, ...(preset || {}) };
  if (!S.pattern) { try { const r = await api("/__gate/api/tunnels"); S.mode = r.mode; S.pattern = r.pattern; } catch { /* the form still works */ } }
  const isSite = edit && t.kind === "site";
  const managed = edit && !!t.app && !isSite;      // an addon's: it decides where it points
  const siteOnly = !edit && !!opts.site;
  const canSite = !edit && !siteOnly && pagesOn();
  const st = { site: isSite || siteOnly, access: t.access || "login" };
  openModal(`
    <h2>${edit ? `Edit ${h(isSite ? displayName(t) : "tunnel-" + t.port)}` : siteOnly ? "Add a site" : "New tunnel"}</h2>
    <p id="fLead">${edit ? (isSite ? "Change the site, its address, or who can open it." : "Change where it points or who can open it.") : "Give a port its own HTTPS address. Behind your Aegis login unless you pick otherwise."}</p>
    <form id="tf" autocomplete="off">
      ${canSite ? `<section class="srt" id="fSrt">
        <label class="srt-head"><span class="srt-ico">${ICON.shield}</span>
          <span class="grow"><span class="srt-t"><b>Secure reverse tunneling mode</b><span class="pill exp">experimental</span></span>
            <span class="faint small">Serve a GitHub or GitLab Pages site on a subdomain of yours, behind a password, through Burrow. From the Burrow Pages addon.</span></span>
          <span class="switch"><input type="checkbox" id="fSiteOn" aria-label="Secure reverse tunneling mode"><i></i></span></label>
      </section>` : ""}
      <div id="fSiteBox" ${st.site ? "" : "hidden"}>
        <label class="field"><span>The site <span class="faint">(GitHub or GitLab Pages)</span></span>
          <input class="input mono" id="fSite" value="${h(isSite ? t.site.url : "")}" placeholder="you.github.io/project or github.com/you/project" spellcheck="false" autocapitalize="none"></label>
        <div class="site-guess faint small" id="fGuess"></div>
      </div>
      <div id="fPortBox" ${st.site ? "hidden" : ""}>
      ${edit ? "" : `<label class="field"><span>Port</span><input class="input mono" id="fPort" inputmode="numeric" placeholder="3000" value="${h(t.port || "")}">
        <div class="chips" id="portChips"><span class="faint mono" style="font-size:11.5px">finding open ports…</span></div></label>`}
      <div class="row">
        <label class="field grow"><span>Target host</span><input class="input mono" id="fHost" value="${h(t.targetHost)}" placeholder="127.0.0.1"></label>
        <label class="field" style="width:120px"><span>Target port</span><input class="input mono" id="fTPort" inputmode="numeric" value="${edit ? t.targetPort : ""}" placeholder="same"></label>
      </div>
      </div>
      <label class="field"><span>Name <span class="faint">(optional; the page title is used otherwise)</span></span><input class="input" id="fName" maxlength="60" value="${h(t.name || "")}"></label>
      <label class="field"><span>Address <span class="faint" id="fSubHint"></span></span>
        <div class="addr"><input class="input mono" id="fSub" maxlength="40" value="${h(t.sub || "")}" placeholder="${h(S.mode === "domain" ? defaultLabel(t.port) : "grafana")}" spellcheck="false" autocapitalize="none"><span class="mono zone">.${h(zoneName() || "your-domain")}</span></div></label>
      <div class="field"><span>Who can open it</span><div id="fAccessBox">${accessSeg("fAccess", st.access, st.site)}</div></div>
      ${pwFields(!!t.locked)}
      <details class="adv" id="fAdv" ${st.site ? "hidden" : ""}><summary>Advanced</summary>
        <div class="row">
          <label class="field grow"><span>Target speaks</span><select class="input" id="fScheme">
            <option value="auto">detect (HTTP or HTTPS)</option><option value="http" ${t.scheme === "http" && edit ? "selected" : ""}>HTTP</option><option value="https" ${t.scheme === "https" && edit ? "selected" : ""}>HTTPS</option></select></label>
        </div>
        <label class="row" style="gap:10px;margin-bottom:14px"><span class="switch"><input type="checkbox" id="fPreserve" ${t.preserveHost ? "checked" : ""}><i></i></span><span style="font-size:13px">Keep the tunnel's Host header <span class="faint">(for apps that need their public name)</span></span></label>
      </details>
      <div class="preview" id="fPreview"></div>
      <div class="err-msg" id="fErr"></div>
      <div class="modal-actions"><button type="button" class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="fGo">${edit ? "Save" : "Create tunnel"}</button></div>
    </form>`, (m) => {
    const portEl = m.querySelector("#fPort"), subEl = m.querySelector("#fSub"), siteEl = m.querySelector("#fSite");
    const draw = () => {
      m.querySelector("#fSiteBox").hidden = !st.site;
      m.querySelector("#fPortBox").hidden = st.site || managed;
      m.querySelector("#fAdv").hidden = st.site || managed;
      if (st.site && st.access === "public") st.access = "login";
      m.querySelector("#fAccessBox").innerHTML = accessSeg("fAccess", st.access, st.site);
      m.querySelector("#fPwBox").hidden = st.access !== "password";
      m.querySelector("#fSubHint").textContent = st.site
        ? (S.mode === "domain" ? "(the subdomain it gets, like docs)" : "(used once a domain is linked)")
        : `(optional; ${S.mode === "domain" ? "your own subdomain, empty for the default" : "used once a domain is linked"})`;
      subEl.placeholder = st.site ? "docs" : S.mode === "domain" ? defaultLabel(t.port) : "grafana";
      if (!edit) {
        m.querySelector("#fGo").textContent = st.site ? "Serve the site" : "Create tunnel";
        m.querySelector("#fLead").textContent = st.site ? "Burrow fetches the site from GitHub or GitLab and serves it on your address, only to whoever has the login or the password."
          : "Give a port its own HTTPS address. Behind your Aegis login unless you pick otherwise.";
      }
      upd();
    };
    const upd = () => {
      const sub = subEl.value.trim().toLowerCase(), pv = m.querySelector("#fPreview");
      if (st.site) {
        const g = siteGuess(siteEl.value);
        m.querySelector("#fGuess").innerHTML = g ? `${h(PROVIDER[g.provider])} · <span class="mono">https://${h(g.url)}</span>` : siteEl.value.trim() ? "GitHub or GitLab Pages addresses only, for now." : "";
        const at = S.mode === "domain" ? (sub ? `https://<b>${h(sub)}</b>.${h(zoneName())}` : `https://<b>…</b>.${h(zoneName())}`) : "a random <b>https://….trycloudflare.com</b> address";
        pv.innerHTML = `${at} <span class="faint">serves</span> ${g ? `<span class="mono">${h(g.url)}</span>` : "the site"} <span class="faint">· ${st.access === "password" ? "behind its own password" : "behind your Aegis login"}</span>`;
      } else pv.innerHTML = previewText(edit ? t.port : (portEl?.value || "").trim() || "PORT", sub);
    };
    m.querySelector("#fSiteOn")?.addEventListener("change", (e) => { st.site = e.target.checked; draw(); (st.site ? siteEl : portEl)?.focus(); });
    m.querySelector("#fAccessBox").addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      st.access = b.dataset.v; draw();
      if (st.access === "password") m.querySelector("#fPw").focus();
    });
    portEl?.addEventListener("input", upd);
    subEl.addEventListener("input", upd);
    siteEl.addEventListener("input", upd);
    draw();
    (isSite ? siteEl : portEl)?.focus();
    if (!edit) {
      (S.ports ? Promise.resolve({ ports: S.ports }) : api("/__gate/api/ports")).then(({ ports }) => {
        S.ports = ports;
        const chips = m.querySelector("#portChips");
        if (!chips) return;
        chips.innerHTML = ports.length ? ports.slice(0, 24).map((p) => {
          const bind = p.addrs.find((a) => a !== "0.0.0.0" && a !== "::" && a !== "*" && !a.startsWith("127.") && a !== "::1");
          const host = p.local ? "127.0.0.1" : (bind || "127.0.0.1");
          return `<button type="button" class="chip${p.tunneled ? " used" : ""}" ${p.tunneled ? "disabled" : ""} data-port="${p.port}" data-host="${h(host)}" title="${h(p.addrs.join(", "))}">${p.port}${p.process ? " · " + h(p.process) : ""}</button>`;
        }).join("") : '<span class="faint mono" style="font-size:11.5px">no listening ports found</span>';
        chips.addEventListener("click", (e) => {
          const b = e.target.closest(".chip"); if (!b || b.disabled) return;
          portEl.value = b.dataset.port; m.querySelector("#fHost").value = b.dataset.host; upd();
        });
      }).catch(() => { const c = m.querySelector("#portChips"); if (c) c.innerHTML = ""; });
    }
    m.querySelector("#tf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = m.querySelector("#fErr"), btn = m.querySelector("#fGo"), label = btn.textContent;
      err.textContent = ""; btn.disabled = true; btn.textContent = edit ? "Saving…" : st.site ? "Checking the site…" : "Creating…";
      try {
        const sub = subEl.value.trim().toLowerCase() || null;
        if (!edit && !st.site && !(portEl.value || "").trim()) throw new Error("Pick a port.");
        if (st.site && !siteEl.value.trim()) throw new Error("Enter the site's address.");
        if (st.site && S.mode === "domain" && !sub) throw new Error("Give the site an address of its own, like docs.");
        const pw = st.access === "password" ? await sealedPw(m, !(t.locked && edit)) : {};
        let body = { name: m.querySelector("#fName").value.trim(), access: st.access, sub, ...pw };
        if (st.site) body.site = siteEl.value.trim();
        else if (!managed) {
          const scheme = m.querySelector("#fScheme").value;
          Object.assign(body, { targetHost: m.querySelector("#fHost").value.trim() || "127.0.0.1",
                                targetPort: m.querySelector("#fTPort").value.trim() || undefined,
                                preserveHost: m.querySelector("#fPreserve").checked });
          if (scheme !== "auto") body.scheme = scheme;
          if (!edit) body.port = portEl.value.trim();
        }
        const res = edit ? await api(`/__gate/api/tunnels/${t.port}`, { method: "PATCH", body: JSON.stringify(body) })
                         : await api("/__gate/api/tunnels", { method: "POST", body: JSON.stringify(body) });
        S.ports = null;
        closeModal();
        toast(edit ? "Saved" : st.site ? `${res.host || "The site"} is live behind ${res.access === "password" ? "its password" : "your login"}` : `tunnel-${res.port} is live`);
        go("detail", res.port);
      } catch (ex) {
        err.textContent = ex.message; btn.disabled = false; btn.textContent = label;
      }
    });
  });
}

// Set or change a tunnel's own password (and switch it to that).
function passwordForm(d) {
  openModal(`<h2>${d.locked ? "Change the password" : "A password of its own"}</h2>
    <p>${h(d.host || displayName(d))} then opens with this password. Your Aegis login keeps working there too.${d.locked ? " Whoever has the old one has to enter the new one." : ""}</p>
    <form id="pwf" autocomplete="off">${pwFields(false)}
      <div class="err-msg" id="pErr"></div>
      <div class="modal-actions"><button type="button" class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="pGo">${d.locked ? "Change it" : "Set it"}</button></div>
    </form>`, (m) => {
    m.querySelector("#fPw").focus();
    m.querySelector("#pwf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const b = m.querySelector("#pGo"), label = b.textContent;
      b.disabled = true; b.textContent = "Sealing…";
      try {
        await patch(d.port, { access: "password", ...(await sealedPw(m, true)) });
        closeModal(); toast("It opens with its own password now"); refresh();
      } catch (ex) { m.querySelector("#pErr").textContent = ex.message; b.disabled = false; b.textContent = label; }
    });
  });
}

function confirmDelete(t) {
  openModal(`<h2>Delete ${h(t.kind === "site" ? displayName(t) : "tunnel-" + t.port)}?</h2>
    <p><span class="mono">${h(t.host || "Its address")}</span> stops working right away, open connections are closed, and its DNS record is removed. ${t.kind === "site" ? `The site itself, on ${h(PROVIDER[t.site.provider] || "Pages")}, is not touched.` : `Whatever runs on port ${t.targetPort} is not touched.`}</p>
    <div class="err-msg" id="dErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn danger" id="dGo">Delete tunnel</button></div>`, (m) => {
    m.querySelector("#dGo").addEventListener("click", async () => {
      const b = m.querySelector("#dGo"); b.disabled = true; b.textContent = "Deleting…";
      try { await api(`/__gate/api/tunnels/${t.port}`, { method: "DELETE" }); closeModal(); toast(`${t.kind === "site" ? displayName(t) : "tunnel-" + t.port} deleted`); go("list"); }
      catch (ex) { m.querySelector("#dErr").textContent = ex.message; b.disabled = false; b.textContent = "Delete tunnel"; }
    });
  });
}

// ------------------------------------------------------------------ events
const patch = (port, body) => api(`/__gate/api/tunnels/${port}`, { method: "PATCH", body: JSON.stringify(body) });

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const act = el.dataset.act;
  if (e.target.closest("[data-stop]") && act === "open") return;     // links/switches inside a card
  const port = Number(el.dataset.port || S.port);
  if (act === "integ" && e.target.closest("[data-stop]")) return;
  try {
    if (act === "open") go("detail", port);
    else if (act === "home") go("list");
    else if (act === "tab") go(["forge", "addons"].includes(el.dataset.v) ? el.dataset.v : "list");
    else if (act === "bridge-check") loadBridge(true);
    else if (act === "bridge-ask") bridgeAsk();
    else if (act === "bridge-manual") { S.manual = !S.manual; render(); if (S.manual) setTimeout(() => document.querySelector(".ab-steps")?.scrollIntoView({ behavior: "smooth", block: "center" }), 50); }
    else if (act === "scan") loadScan(true);
    else if (act === "ad-add") addAddon(el.dataset.src, el);
    else if (act === "ad-install") installForm(el.dataset.id);
    else if (act === "ad-update") jobRun(el.dataset.id, "update", {});
    else if (act === "ad-check") checkUpdates(el.dataset.id);
    else if (act === "ad-action") { const go2 = () => jobRun(el.dataset.id, "action", { action: el.dataset.action }); if (el.dataset.confirm && !confirm(el.dataset.confirm)) return; go2(); }
    else if (act === "ad-uninstall") uninstallForm(el.dataset.id);
    else if (act === "ad-remove") { await api(`/__gate/api/addons/${el.dataset.id}/remove`, { method: "POST", body: "{}" }); toast("Removed"); S.scan = null; refresh(); }
    else if (act === "ad-share") { el.disabled = true; await api(`/__gate/api/addons/${el.dataset.id}/share`, { method: "POST", body: JSON.stringify({ on: el.dataset.on === "1" }) }); toast(el.dataset.on === "1" ? "Published through Burrow" : "Unpublished"); refresh(); }
    else if (act === "job-cancel") await api(`/__gate/api/addons/jobs/${el.dataset.job}/cancel`, { method: "POST", body: "{}" });
    else if (act === "new") tunnelForm();
    else if (act === "site-new") tunnelForm(null, null, { site: true });
    else if (act === "close") closeModal();
    else if (act === "copy") { e.stopPropagation(); await navigator.clipboard.writeText(el.dataset.text); toast("Link copied"); }
    else if (act === "edit") tunnelForm(S.detail);
    else if (act === "delete") confirmDelete(S.detail);
    else if (act === "access") {
      const v = el.dataset.v;
      if (v === "password" && !S.detail?.locked) { passwordForm(S.detail); return; }
      await patch(port, { access: v });
      toast(v === "public" ? "Anyone with the link can open it" : v === "password" ? "It opens with its own password (or your login)" : "Login required"); refresh();
    }
    else if (act === "password") passwordForm(S.detail);
    else if (act === "kick") { const r = await api(`/__gate/api/tunnels/${port}/kick`, { method: "POST", body: JSON.stringify({ ip: el.dataset.ip }) }); toast(`Closed ${r.kicked} connection${r.kicked === 1 ? "" : "s"}`); refresh(); }
    else if (act === "block") { await patch(port, { block: el.dataset.ip }); toast(`${el.dataset.ip} blocked`); refresh(); }
    else if (act === "unblock") { await patch(port, { unblock: el.dataset.ip }); toast(`${el.dataset.ip} unblocked`); refresh(); }
    else if (act === "reset") { await patch(port, { resetStats: true }); toast("Stats reset"); refresh(); }
    else if (act === "integ") { if (!e.target.closest("[data-stop]")) go("integ", el.dataset.id); }
    else if (act === "desk") {
      el.disabled = true; const what = el.dataset.do;
      toast(`${what === "stop" ? "Stopping" : what === "start" ? "Starting" : "Restarting"} ${el.dataset.name}…`);
      await api(`/__gate/api/integrations/${encodeURIComponent(S.integ)}/desktops/${encodeURIComponent(el.dataset.name)}/${what}`, { method: "POST", body: "{}" });
      toast(`${el.dataset.name}: ${what === "stop" ? "stopped" : what === "start" ? "started" : "restarted"}`); refresh();
    }
    else if (act === "publish") {
      el.disabled = true;
      const res = await api("/__gate/api/tunnels", { method: "POST", body: JSON.stringify({ port: Number(el.dataset.port), targetHost: "127.0.0.1", name: el.dataset.title, access: "login" }) });
      toast(res.url ? `Published at ${res.host}` : "Published; its address is on the way"); refresh();
    }
    else if (act === "unpublish") {
      el.disabled = true;
      await api(`/__gate/api/tunnels/${el.dataset.port}`, { method: "DELETE" });
      toast(`${el.dataset.title} is no longer published`); refresh();
    }
  } catch (ex) { toast(ex.message); }
});

document.addEventListener("change", async (e) => {
  const el = e.target.closest('[data-act="toggle"]');
  if (!el) return;
  e.stopPropagation();
  try { await patch(Number(el.dataset.port), { enabled: el.checked }); toast(el.checked ? "Tunnel on" : "Tunnel paused"); refresh(); }
  catch (ex) { el.checked = !el.checked; toast(ex.message); }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && S.modal) closeModal();
  const pr = e.target.closest?.(".prow");
  if (pr && e.key === "Enter" && e.target === pr) go("detail", Number(pr.dataset.port));
  const i = e.target.closest?.(".integ");
  if (i && (e.key === "Enter" || e.key === " ") && e.target === i) { e.preventDefault(); go("integ", i.dataset.id); }
});
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
window.addEventListener("popstate", fromHash);
// a favicon that fails to load falls back to the letter
document.addEventListener("error", (e) => {
  const img = e.target;
  if (img.tagName === "IMG" && img.dataset.fallback) img.parentElement.textContent = img.dataset.fallback;
}, true);

chrome("tunnels").then((me) => { S.me = me; loadPanels(); render(); });
fromHash();
