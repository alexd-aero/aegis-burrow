// Shared by the dashboard pages: API calls, the top bar, small formatters.
// No inline handlers anywhere (strict CSP): pages wire everything through
// data-act attributes and delegated listeners.

export const $ = (s, el = document) => el.querySelector(s);
export const h = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Gate": "1", ...(opts.headers || {}) } });
  if (r.status === 401) { location.href = "/__gate/login?next=" + encodeURIComponent(location.pathname + location.hash); throw new Error("Signed out"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
export const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

export function toast(msg) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg; document.body.append(t);
  setTimeout(() => t.remove(), 2600);
}

export function setLive(ok, text) {
  const el = $("#liveState");
  if (el) el.innerHTML = `<i class="dot ${ok ? "ok" : "err"}"></i><span>${h(text)}</span>`;
}

export const ago = (t) => { if (!t) return "never"; const s = Math.max(0, (Date.now() - t) / 1000); return s < 5 ? "now" : s < 60 ? Math.floor(s) + "s ago" : s < 3600 ? Math.floor(s / 60) + "m ago" : s < 86400 ? Math.floor(s / 3600) + "h ago" : Math.floor(s / 86400) + "d ago"; };

export const ICONS = {
  arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  ext: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>',
  tunnel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 18 0"/><path d="M7 12a5 5 0 0 1 10 0"/><circle cx="12" cy="12" r="1.5"/><path d="M12 13.5V20"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4 5.5v6c0 4.9 3.4 8.8 8 10 4.6-1.2 8-5.1 8-10v-6l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>',
};

// The top bar: show the sections this install has, mark the current one.
export async function chrome(active) {
  document.querySelectorAll("[data-nav]").forEach((a) => {
    if (a.dataset.nav === active) { a.classList.add("on"); a.setAttribute("aria-current", "page"); }
  });
  let me = null;
  try { me = await api("/__gate/api/me"); } catch { return null; }
  const termix = document.querySelector('[data-nav="termix"]');
  if (termix) termix.hidden = !me.termix;
  const burrow = document.querySelector('[data-nav="tunnels"]');
  if (burrow && !me.modules?.burrow && active !== "tunnels") burrow.hidden = true;
  updateBanner(me, document.querySelector("main"));
  freshUpdate(me, document.querySelector("main"));
  notices(me);
  dashSwitch(me);
  return me;
}

// ------------------------------------------------------------- your dashboards
// With other domains that have a dashboard name, a switcher next to the bell:
// every dashboard of yours, and a click opens it signed in (this dashboard
// hands it a ticket), from whichever one you are on.
export function dashSwitch(me) {
  const list = me?.dashboards || [];
  document.querySelector(".ds")?.remove();
  if (list.length < 2) return;
  const host = document.querySelector(".top-r") || document.querySelector(".hello");
  if (!host) return;
  const here = list.find((d) => d.current);
  const next = location.pathname + location.search + location.hash;
  const wrap = document.createElement("div");
  wrap.className = "ds";
  wrap.innerHTML = `<button type="button" class="ds-btn" aria-haspopup="true" aria-expanded="false" title="Your dashboards">${ICONS.globe}<span class="ds-cur">${h(here ? here.zone : "Dashboards")}</span><b class="ds-n">${list.length}</b></button>
    <div class="ds-pop" hidden role="dialog" aria-label="Your dashboards"><div class="nt-head"><b>Your dashboards</b><span class="spacer"></span><span class="muted small">one sign-in for all</span></div>
    <ul class="ds-list">${list.map((d) => `<li>${d.current
      ? `<div class="ds-row on" aria-current="page"><span class="ds-ic">${ICONS.globe}</span><span class="ds-two"><b>${h(d.host)}</b><span>${d.main ? "Main dashboard" : h(d.zone)} · you're here</span></span></div>`
      : `<a class="ds-row" href="/__gate/sso?to=${encodeURIComponent(d.host)}&amp;next=${encodeURIComponent(next)}"><span class="ds-ic">${ICONS.globe}</span><span class="ds-two"><b>${h(d.host)}</b><span>${d.main ? "Main dashboard" : h(d.zone)}</span></span>${ICONS.arrow}</a>`}</li>`).join("")}</ul>
    <p class="ds-foot muted small">Tunnels on every domain are on the Burrow page of any of them.</p></div>`;
  const anchor = host.querySelector(".nt") || host.querySelector(".gear") || host.querySelector(".out") || host.querySelector('a[href="/__gate/logout"]');
  anchor ? anchor.before(wrap) : host.prepend(wrap);
  const btn = wrap.querySelector(".ds-btn"), pop = wrap.querySelector(".ds-pop");
  const close = () => { pop.hidden = true; btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", (e) => { e.stopPropagation(); const open = pop.hidden; pop.hidden = !open; btn.setAttribute("aria-expanded", String(open)); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".ds")) close(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
}

// ------------------------------------------------------------------ notices
// Warnings addons put on the dashboard (Bulwark: attacks, bans, waves): a bell
// in the top bar with the unread count, a list grouped by day (each notice with
// its addon's logo, and its addresses as rows that open in the addon), and a
// banner for an unread critical one. Checked again every 30 s.
const BELL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8.4a6 6 0 1 0-12 0c0 4.6-1.4 6.4-2.6 7.6-.4.4-.1 1 .4 1h16.4c.5 0 .8-.6.4-1-1.2-1.2-2.6-3-2.6-7.6"/><path d="M10.2 20.2a2 2 0 0 0 3.6 0"/></svg>';
const SRC = (s) => s === "aegis" ? "Aegis" : s.charAt(0).toUpperCase() + s.slice(1);
const flagOf = (cc) => /^[A-Z]{2}$/.test(cc || "") ? String.fromCodePoint(...[...cc].map((c) => 127397 + c.charCodeAt(0))) : "";
const srcLogo = (s) => s === "aegis" ? "/__gate/logos/aegis-burrow.svg" : `/__gate/api/addons/${encodeURIComponent(s)}/image`;
const dayOf = (t) => { const d = new Date(t), today = new Date(); const y = new Date(); y.setDate(today.getDate() - 1);
  return d.toDateString() === today.toDateString() ? "Today" : d.toDateString() === y.toDateString() ? "Yesterday" : d.toLocaleDateString([], { weekday: "long", month: "short", day: "numeric" }); };
let nState = null, nTimer = null, nOpen = new Set();
export function notices(me) {
  nState = me?.notices || nState;
  if (!nState) return;
  let bell = document.querySelector(".nt-bell");
  if (!bell) {
    const host = document.querySelector(".top-r") || document.querySelector(".hello");
    if (!host) return;
    const wrap = document.createElement("div");
    wrap.className = "nt";
    wrap.innerHTML = `<button type="button" class="nt-bell" aria-label="Notices" aria-haspopup="true" aria-expanded="false">${BELL}<b class="nt-count" hidden></b></button><div class="nt-pop" hidden role="dialog" aria-label="Notices"></div>`;
    const anchor = host.querySelector(".gear") || host.querySelector(".out") || host.querySelector('a[href="/__gate/logout"]');
    anchor ? anchor.before(wrap) : host.prepend(wrap);
    bell = wrap.querySelector(".nt-bell");
    bell.addEventListener("click", (e) => { e.stopPropagation(); togglePop(); });
    document.addEventListener("click", (e) => { if (!e.target.closest(".nt")) closePop(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePop(); });
    clearInterval(nTimer);
    nTimer = setInterval(async () => { if (document.hidden) return; try { const j = await api("/__gate/api/notices"); nState = j; paintBell(); noticeBanner(); if (!document.querySelector(".nt-pop").hidden) paintPop(j.notices); } catch { /* offline */ } }, 30000);
  }
  paintBell(); noticeBanner();
}
function paintBell() {
  const c = document.querySelector(".nt-count"), b = document.querySelector(".nt-bell");
  if (!c) return;
  c.hidden = !nState.unread; c.textContent = nState.unread > 99 ? "99+" : nState.unread;
  b.dataset.level = nState.worst || "";
  b.setAttribute("aria-label", nState.unread ? `Notices: ${nState.unread} unread` : "Notices");
}
async function togglePop() {
  const pop = document.querySelector(".nt-pop"), b = document.querySelector(".nt-bell");
  if (!pop.hidden) return closePop();
  pop.hidden = false; b.setAttribute("aria-expanded", "true");
  pop.innerHTML = '<p class="muted small" style="padding:16px">Loading…</p>';
  try { const j = await api("/__gate/api/notices"); nState = j; paintPop(j.notices); } catch (e) { pop.innerHTML = `<p class="err-msg" style="padding:16px">${h(e.message)}</p>`; }
}
function closePop() { const pop = document.querySelector(".nt-pop"); if (pop && !pop.hidden) { pop.hidden = true; document.querySelector(".nt-bell")?.setAttribute("aria-expanded", "false"); } }
// one address (or thing) a notice is about
const itemRow = (i) => `<${i.link ? `a href="${h(i.link)}"` : "div"} class="nt-row" data-nt-go>
    <span class="nt-flag" aria-hidden="true">${flagOf(i.cc) || "·"}</span><span class="nt-two"><span class="nt-lbl">${h(i.label)}</span>${i.sub ? `<span class="nt-sub" title="${h(i.sub)}">${h(i.sub)}</span>` : ""}</span>
    ${i.tag ? `<span class="nt-tag">${h(i.tag)}</span>` : "<span></span>"}</${i.link ? "a" : "div"}>`;
function noticeCard(n) {
  const items = n.items || [], open = nOpen.has(n.id), shown = open ? items : items.slice(0, 4);
  const more = (n.total || items.length) - shown.length;
  return `<li class="nt-card2 ${h(n.level)}${n.read ? "" : " unread"}" data-id="${h(n.id)}">
    <div class="nt-h"><img class="nt-src" src="${h(srcLogo(n.source))}" alt="" width="20" height="20" onerror="this.style.visibility='hidden'">
      <div class="nt-ht"><b>${h(n.title)}</b><span class="nt-meta">${h(SRC(n.source))} · ${h(ago(n.t))}${n.first && n.t - n.first > 60000 ? ` · since ${h(ago(n.first))}` : ""}</span></div>
      ${n.read ? "" : '<i class="nt-unread" title="Unread"></i>'}</div>
    ${n.body ? `<p class="nt-body">${h(n.body)}</p>` : ""}
    ${shown.length ? `<div class="nt-rows">${shown.map(itemRow).join("")}</div>` : ""}
    ${more > 0 && items.length > shown.length ? `<button type="button" class="nt-more" data-nt-more>Show ${items.length - shown.length} more</button>` : more > 0 ? `<span class="nt-more faint">+${more} earlier</span>` : ""}
    <div class="nt-f">${n.link ? `<a class="btn sm" href="${h(n.link)}" data-nt-go>Open in ${h(SRC(n.source))}</a>` : ""}${n.read ? "" : '<button type="button" class="btn ghost sm" data-nt-read>Mark read</button>'}</div></li>`;
}
function paintPop(list) {
  const pop = document.querySelector(".nt-pop");
  let html = "", last = null;
  for (const n of list) { const d = dayOf(n.t); if (d !== last) { html += `<li class="nt-day">${h(d)}</li>`; last = d; } html += noticeCard(n); }
  pop.innerHTML = `<div class="nt-head"><b>Notices</b>${nState.unread ? `<span class="nt-chip">${nState.unread} new</span>` : ""}<span class="spacer"></span>
      ${nState.unread ? '<button type="button" class="btn ghost sm" data-nt="read">Mark all read</button>' : ""}
      ${list.some((n) => n.read) ? '<button type="button" class="btn ghost sm" data-nt="clear">Clear read</button>' : ""}</div>
    <ul class="nt-list">${html || '<li class="nt-empty"><b>All quiet.</b><br>Warnings from Bulwark and other addons show up here: attacks, bans, waves.</li>'}</ul>`;
  pop.onclick = async (e) => {
    e.stopPropagation();
    const b = e.target.closest("[data-nt]"), card = e.target.closest(".nt-card2");
    const reread = async (body) => { const j = await api(`/__gate/api/notices/${body.clear ? "clear" : "read"}`, { method: "POST", body: JSON.stringify(body) }); nState = j; paintBell(); noticeBanner(); return j; };
    if (b) { const j = await reread(b.dataset.nt === "clear" ? { clear: true, all: true } : { all: true }); paintPop(j.notices); return; }
    if (!card) return;
    if (e.target.closest("[data-nt-more]")) { nOpen.add(card.dataset.id); paintPop(list); return; }
    if (e.target.closest("[data-nt-read]")) { const j = await reread({ ids: [card.dataset.id] }); paintPop(j.notices); return; }
    if (e.target.closest("[data-nt-go]") && card.classList.contains("unread")) reread({ ids: [card.dataset.id] }).catch(() => {});      // following it counts as reading it
  };
}
function noticeBanner() {
  const b = nState?.banner, cur = document.querySelector(".nt-banner");
  if (!b) { cur?.remove(); return; }
  if (cur?.dataset.id === b.id && cur.dataset.t === String(b.t)) return;
  cur?.remove();
  const main = document.querySelector("#opts") || document.querySelector("main");
  if (!main) return;
  const el = document.createElement("section");
  el.className = "nt-banner"; el.dataset.id = b.id; el.dataset.t = String(b.t); el.setAttribute("role", "alert");
  const chips = (b.items || []).map((i) => `<span class="nt-pill">${flagOf(i.cc)} ${h(i.label)}</span>`).join("") + ((b.total || 0) > (b.items || []).length ? `<span class="nt-pill faint">+${b.total - b.items.length}</span>` : "");
  el.innerHTML = `<div class="nt-bcard"><img class="nt-src" src="${h(srcLogo(b.source))}" alt="" width="28" height="28" onerror="this.style.visibility='hidden'">
      <div class="nt-txt"><b>${h(b.title)}</b>${b.body ? `<p>${h(b.body)}</p>` : ""}${chips ? `<div class="nt-pills">${chips}</div>` : ""}<div class="nt-meta">${h(SRC(b.source))} · ${h(ago(b.t))}</div></div>
      <div class="nt-acts">${b.link ? `<a class="btn sm" href="${h(b.link)}">Open</a>` : ""}<button type="button" class="btn ghost sm" data-nt-dismiss>Dismiss</button></div></div>`;
  main.before(el);
  el.querySelector("[data-nt-dismiss]").addEventListener("click", async () => {
    const j = await api("/__gate/api/notices/read", { method: "POST", body: JSON.stringify({ ids: [b.id] }) }); nState = j; paintBell(); el.remove(); noticeBanner();
  });
  el.querySelector("a.btn")?.addEventListener("click", () => { api("/__gate/api/notices/read", { method: "POST", body: JSON.stringify({ ids: [b.id] }) }).catch(() => {}); });
}

// ------------------------------------------------------------------ updates
// The update card: the same look as Selkies Forge's (stealth theme): a glowing
// green orb, a NEW chip, the version going from → to. Used by the banner on
// every page and by Settings → Updates.
export const UPD = {
  down: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M7 7l10 10M17 7 7 17"/></svg>',
  arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
};
// ------------------------------------------------------------------ addon updates
// One card for an addon with an update, drawn the same on the home page and on
// the Burrow page (AU holds what both know: the updates, a running update, one
// just done). The addon dresses its own card through its manifest (the Weft
// field "update_card", read from the new version): a theme or a colour of its
// own, a style, a badge, an icon, a title, a tagline, highlights, the button's
// words, how urgent it is, and a link to its release notes.
export const AU = { list: [], job: {}, done: {} };
const AU_ICONS = {
  download: null, // UPD.down
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6L12 3Z"/><path d="m8.8 12.2 2.3 2.3 4.3-4.6"/></svg>',
  bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"><path d="M13 2.5 4.5 13.5h6.5l-1 8 8.5-11h-6.5l1-8Z"/></svg>',
  spark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"><path d="M12 3c.6 4.6 2.4 6.4 7 7-4.6.6-6.4 2.4-7 7-.6-4.6-2.4-6.4-7-7 4.6-.6 6.4-2.4 7-7Z"/><path d="M19 15.5c.25 1.6.9 2.25 2.5 2.5-1.6.25-2.25.9-2.5 2.5-.25-1.6-.9-2.25-2.5-2.5 1.6-.25 2.25-.9 2.5-2.5Z"/></svg>',
  heart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"><path d="M12 20s-7.5-4.6-7.5-10.2A4.3 4.3 0 0 1 12 7a4.3 4.3 0 0 1 7.5 2.8C19.5 15.4 12 20 12 20Z"/></svg>',
  star: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"><path d="m12 3.5 2.6 5.4 5.9.8-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.8L12 3.5Z"/></svg>',
  wrench: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3.5 17.3a1.8 1.8 0 0 0 2.6 2.6l5.8-5.8a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.4-.6-.6-2.4 2.6-2.6Z"/></svg>',
  rocket: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4.5c3-1.6 5.4-1.3 5.5-1 .3.1.6 2.5-1 5.5L13 14.5 9.5 11 14 4.5Z"/><path d="M9.5 11 6 11.5 4 14l3.5.5M13 14.5l-.5 3.5L10 20l-.5-3.5"/><path d="M6 18c-1 .5-1.8 1.4-2 2.5 1.1-.2 2-1 2.5-2"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/></svg>',
  bug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><rect x="7" y="7.5" width="10" height="12.5" rx="5"/><path d="M12 11v9M7 13H3.5M20.5 13H17M7.5 17.5 4.5 19.5M16.5 17.5l3 2M8.5 8 6.5 5.5M15.5 8l2-2.5"/></svg>',
};
const AU_THEMES = new Set(["green", "blue", "red", "orange", "amber", "purple", "pink", "teal", "gray"]);
const AU_STYLES = new Set(["glow", "solid", "outline", "minimal"]);
const AU_URGENT = {
  security: { theme: "red", badge: "SECURITY", icon: "shield", line: "A security update: install it soon." },
  critical: { theme: "red", badge: "CRITICAL", icon: "shield", line: "A critical fix: install it now." },
  important: { theme: "orange", badge: "IMPORTANT", icon: "bolt", line: "" },
  recommended: { badge: "RECOMMENDED", line: "" },
  normal: {},
};
export const auLaterKey = (u) => `burrow-addon-later-${u.id}-${u.commit || u.latest}`;
const auLaterGet = (u) => { try { return localStorage.getItem(auLaterKey(u)) === "1"; } catch { return false; } };
export const auLaterSet = (u) => { try { localStorage.setItem(auLaterKey(u), "1"); } catch { /* private window */ } };
// a colour of the addon's own: the card's five shades from one hex
function accentStyle(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
  if (!m) return "";
  const n = parseInt(m[1], 16), c = [n >> 16, (n >> 8) & 255, n & 255];
  const mix = (t, k) => "#" + c.map((x) => Math.round(x + (t - x) * k).toString(16).padStart(2, "0")).join("");
  const lum = (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255;
  return `--upd:#${m[1]};--upd-hi:${mix(255, 0.4)};--upd-deep:${mix(0, 0.3)};--upd-ink:${lum > 0.55 ? mix(0, 0.88) : "#ffffff"};--upd-rgb:${c.join(",")}`;
}
// the card's look: urgency first, then what the addon asked for
function auLook(card) {
  const c = card || {}, u = AU_URGENT[c.urgency] || {};
  return { theme: AU_THEMES.has(c.theme) ? c.theme : u.theme || "green", style: AU_STYLES.has(c.style) ? c.style : "glow",
           badge: c.badge != null ? String(c.badge) : u.badge || "NEW", icon: AU_ICONS[c.icon] || AU_ICONS[u.icon] || UPD.down,
           accent: c.accent || "", line: u.line || "", urgency: c.urgency || "normal" };
}
const fill = (t, u, to) => String(t).replaceAll("{name}", u.name).replaceAll("{version}", to || u.latest || "").replaceAll("{from}", u.version || "");
// whatsNew: "check" (the Burrow page asks Burrow), or a link (the home page)
export function addonUpdCard(id, { whatsNew = "check" } = {}) {
  const job = AU.job[id], done = AU.done[id], u = AU.list.find((x) => x.id === id) || job?.u;
  const logo = (x) => x?.logo ? `<img class="uc-logo" src="${h(x.logo)}" alt="">` : "";
  const short = (c) => String(c || "").slice(0, 7);
  const card = (u || done)?.card || null, look = auLook(card);
  let html;
  if (done) {
    html = updHero("ok", UPD.check, `${logo(done)}${h(done.name)} is up to date`,
      `Updated to <span class="uc-pill">v${h(done.to)}</span> just now${done.to !== done.from ? `, from v${h(done.from)}` : ""}. Everything it had set up was kept.`) +
      `<div class="uc-foot"><span class="spacer"></span><button class="uc-btn" data-act="upd-done" data-id="${h(id)}">Done</button></div>`;
  } else if (job?.state === "error") {
    html = updHero("bad", UPD.x, `${logo(u)}${h(u.name)} didn't update`, h(job.error || "The update stopped.") + " What it had before is still in place.") +
      `<div class="uc-foot"><span class="spacer"></span><button class="uc-btn" data-act="upd-done" data-id="${h(id)}">Close</button>
        <button class="uc-go" data-act="upd-go" data-id="${h(id)}">${UPD.down}<span>Try again</span></button></div>`;
  } else if (u && (job || !auLaterGet(u))) {
    const to = u.latest && u.latest !== u.version ? u.latest : null, run = !!job;
    const title = card?.title ? h(fill(card.title, u, to)) : `${h(u.name)} update`;
    const badge = look.badge ? ` <span class="new-chip">${h(look.badge.slice(0, 14))}</span>` : "";
    const base = `${to ? `<span class="uc-pill">v${h(to)}</span> is ready to install` : `Commit <span class="mono">${h(short(u.commit))}</span> is ready to install`}${!card?.tagline && u.subject ? ` · ${h(u.subject)}` : ""}.`;
    const sub = `${card?.tagline ? `<span class="uc-line">${h(card.tagline)}</span>` : ""}${look.line ? `<b class="uc-urgent">${h(look.line)}</b> ` : ""}${base} Its settings and everything it set up are kept.`
      + (card?.highlights?.length ? `<ul class="uc-hl">${card.highlights.slice(0, 5).map((x) => `<li>${h(x)}</li>`).join("")}</ul>` : "");
    html = updHero("new", look.icon, `${logo(u)}${title}${badge}`, sub,
      to ? verJump(u.version, to) : `<div class="uc-ver"><span class="mono">${h(short(u.from))}</span>${UPD.arrow}<b class="mono">${h(short(u.commit))}</b></div>`) +
      `<div class="uc-foot"><span class="uc-when">${run ? h(job.phase || "Updating…") : `Checked ${h(ago(u.checked))}${u.count ? ` · ${u.count} new commit${u.count === 1 ? "" : "s"}` : ""}`}</span><span class="spacer"></span>
        ${run ? "" : `${card?.notes ? `<a class="uc-btn" href="${h(card.notes)}" target="_blank" rel="noopener">Release notes</a>` : whatsNew === "check" ? `<button class="uc-btn" data-act="ad-check" data-id="${h(id)}">What's new</button>` : `<a class="uc-btn" href="${h(whatsNew)}">What's new</a>`}<button class="uc-btn" data-act="upd-later" data-id="${h(id)}">Later</button>`}
        <button class="uc-go" data-act="upd-go" data-id="${h(id)}" ${run ? "disabled" : ""}>${run ? '<span class="uc-spin sm"></span><span>Updating…</span>' : `${UPD.down}<span>${h(card?.button ? fill(card.button, u, to) : `Update${to ? ` to v${to}` : ""}`)}</span>`}</button></div>`;
  } else return "";
  const theme = done ? "green" : look.theme, style = done ? "glow" : look.style;
  return `<section class="addon-upd" data-theme="${theme}" data-style="${style}" data-urgency="${done ? "normal" : look.urgency}"${!done && look.accent ? ` style="${accentStyle(look.accent)}"` : ""} aria-label="${h((u || done).name)} update">${html}</section>`;
}
// install it; render() after each step; after(id) once the new copy runs
export async function updateAddon(id, render, after) {
  const u = AU.list.find((x) => x.id === id) || AU.job[id]?.u;
  if (!u || AU.job[id]?.state === "running") return;
  AU.job[id] = { u, state: "running", phase: "Starting…" };
  render();
  let job;
  try { job = (await api(`/__gate/api/addons/${id}/update`, { method: "POST", body: "{}" })).job; }
  catch (e) { AU.job[id] = { u, state: "error", error: e.message }; render(); return; }
  let v = job;
  for (let miss = 0; v.state === "running" && miss < 30;) {
    await new Promise((ok) => setTimeout(ok, 800));
    try { v = await api(`/__gate/api/addons/jobs/${job.id}?since=1e9`); miss = 0; } catch { miss++; continue; }
    AU.job[id] = { u, state: v.state, phase: v.phase, error: v.error };
    render();
  }
  if (v.state !== "done") { AU.job[id] = { u, state: "error", error: v.error || "Lost track of the update." }; render(); return; }
  delete AU.job[id];
  AU.done[id] = { name: u.name, logo: u.logo, from: u.version, to: v.result?.version || u.latest || u.version, card: u.card };
  AU.list = AU.list.filter((x) => x.id !== id);
  await after?.(id);
  render();
}
// the card's buttons (data-act upd-go / upd-later / upd-done); true when handled
export function addonUpdClick(el, render, after) {
  const act = el?.dataset.act, id = el?.dataset.id;
  if (act === "upd-go") { updateAddon(id, render, after); return true; }
  if (act === "upd-later") { const u = AU.list.find((x) => x.id === id); if (u) auLaterSet(u); render(); return true; }
  if (act === "upd-done") { delete AU.done[id]; delete AU.job[id]; render(); return true; }
  return false;
}

export function updHero(kind, icon, title, sub, extra = "") {
  return `<div class="uc-hero ${kind}"><div class="uc-orb">${icon}</div>
    <div class="uc-txt"><div class="uc-title">${title}</div><div class="uc-sub">${sub}</div></div>${extra}</div>`;
}
export const verJump = (from, to) => `<div class="uc-ver"><span>v${h(from)}</span>${UPD.arrow}<b>v${h(to)}</b></div>`;

// Install the update, then wait for the new version to answer and reload.
export async function runUpdate(onPhase) {
  onPhase("Downloading and installing…");
  const health = () => fetch("/__gate/health", { cache: "no-store" }).then((x) => x.json());
  const before = (await health().catch(() => ({}))).version;
  const r = await post("/__gate/api/update/apply");
  if (r.job?.state === "error") throw new Error(r.job.error);
  if (!r.job?.to) { onPhase("Already up to date."); return; }
  if (r.scope === "manual") { onPhase(`Installed ${r.job.to}. Restart Aegis × Burrow with whatever runs it to finish.`); return; }
  onPhase(`Installed ${r.job.to}. Restarting…`);
  const t0 = Date.now();
  for (;;) {
    await new Promise((ok) => setTimeout(ok, 1500));
    try {
      // back up on a new version (whichever it is): reload into it
      const v = await health();
      if (v.version && v.version !== before) { location.reload(); return; }
    } catch { /* restarting */ }
    if (Date.now() - t0 > 120000) { onPhase("It is taking a while to come back. Reload in a minute, or run: aegis status"); return; }
  }
}

const seen = (k) => { try { return localStorage.getItem(k) === "1"; } catch { return false; } };
const hide = (k) => { try { localStorage.setItem(k, "1"); } catch { /* private window */ } };

// Ask the gate for a check no older than two minutes, then redraw the banner:
// a new version shows up as soon as the page opens, not hours later.
export async function freshUpdate(me, before) {
  if (!me || !me.update) return;
  try {
    const u = await api("/__gate/api/update?fresh=1");
    const was = me.update;
    me.update = { ...was, current: u.current, latest: u.latest, available: u.available, checked: u.checked, title: u.title, auto: u.auto, justUpdated: u.justUpdated };
    if (u.available !== was.available || u.latest !== was.latest) updateBanner(me, before);
  } catch { /* offline: the banner stays as it was */ }
}

// The banner: an update waiting, or the one that just happened.
export function updateBanner(me, before) {
  const u = me && me.update;
  document.querySelector(".upd-banner")?.remove();
  if (!u || !before) return;
  let key, html;
  if (u.available && u.latest) {
    key = `aegis-upd-later-${u.latest}`;
    if (seen(key)) return;
    html = updHero("new", UPD.down, 'Update available <span class="new-chip">NEW</span>',
      `Aegis × Burrow <span class="uc-pill">v${h(u.latest)}</span> is ready to install${u.title ? ` · ${h(u.title)}` : ""}. Your login, domain and tunnels are kept.`,
      verJump(u.current, u.latest)) +
      `<div class="uc-foot"><span class="uc-when" id="updPhase">${u.auto ? "Auto-update is on: it installs by itself." : `Checked ${h(ago(u.checked))}`}</span><span class="spacer"></span>
        <a class="uc-btn" href="/__gate/settings#updates">What's new</a><button class="uc-btn" data-upd="later">Later</button>
        <button class="uc-go" data-upd="go">${UPD.down}<span>Update to v${h(u.latest)}</span></button></div>`;
  } else if (u.justUpdated) {
    key = `aegis-upd-done-${u.current}`;
    if (seen(key)) return;
    html = updHero("ok", UPD.check, "You're up to date",
      `Updated to <span class="uc-pill">v${h(u.current)}</span> ${h(ago(u.justUpdated.at) === "now" ? "just now" : ago(u.justUpdated.at))}, from v${h(u.justUpdated.from)}. Everything you set up was kept.`) +
      `<div class="uc-foot"><span class="spacer"></span><a class="uc-btn" href="/__gate/settings#updates">What's new</a><button class="uc-btn" data-upd="later">Done</button></div>`;
  } else return;
  const el = document.createElement("section");
  el.className = "upd-banner";
  el.setAttribute("aria-label", "Updates");
  el.innerHTML = html;
  before.before(el);
  el.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-upd]");
    if (!b) return;
    if (b.dataset.upd === "later") { hide(key); el.remove(); return; }
    b.disabled = true; b.innerHTML = '<span class="uc-spin sm"></span><span>Updating…</span>';
    try { await runUpdate((t) => { const p = el.querySelector("#updPhase"); if (p) p.textContent = t; }); }
    catch (ex) { toast(ex.message); b.disabled = false; b.innerHTML = `${UPD.down}<span>Try again</span>`; }
  });
}
