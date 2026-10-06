// The home page: one tile per app behind the gate. What shows, in what
// order, under which name, and any links of your own are yours to set with
// Settings → Customize the home page (/?customize=1; the gear opens Settings).
// Saved in data/state.json (home).
import { $, h, api, post, toast, ICONS, updateBanner, freshUpdate } from "./common.js";

const opts = $("#opts"), extra = $("#extra");
const S = { me: null, draft: null, termixJob: false };

const GEAR = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>';
const LINK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>';
const UP = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 15 6-6 6 6"/></svg>';
const DOWN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';
const EYE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYEOFF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18M10.6 5.1A10.6 10.6 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.2M6.6 6.6C3.8 8.4 2 12 2 12s3.5 7 10 7c1.8 0 3.4-.5 4.8-1.3"/></svg>';
const TRASH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>';

// Every tile this install could show, before your choices apply.
function available(me) {
  const out = [];
  if (me.termix) out.push({ id: "termix", href: "/__gate/open/termix", img: "/__gate/logos/termix.svg", title: "Termix", text: "SSH terminals, files and hosts.", foot: location.host });
  if (me.modules.burrow) out.push({ id: "burrow", href: "/__gate/tunnels", img: "/__gate/logos/burrow.svg", title: "Burrow",
    text: "Publish a port on its own address, with live traffic and clients.", foot: me.domain ? `tunnel-PORT-${me.domain.mainHost}` : "trycloudflare.com" });
  for (const i of me.integrations) {
    out.push(i.full
      ? { id: "app:" + i.id, href: `/__gate/tunnels#/i/${encodeURIComponent(i.id)}`, img: i.logo, title: i.name, text: "Desktops, their links and tunnels, start and stop.", foot: i.version ? `v${i.version}` : "connected" }
      : { id: "app:" + i.id, href: i.dashboard, ext: true, img: i.logo, title: i.name, text: "Open its dashboard.", foot: i.version ? `v${i.version}` : "connected" });
  }
  for (const l of (me.home?.links || [])) {
    let host = l.url;
    try { host = new URL(l.url, location.href).host; } catch { /* keep */ }
    out.push({ id: l.id, href: l.url, ext: !l.url.startsWith("/"), link: true, icon: l.icon, title: l.title, text: l.text || "", foot: host });
  }
  return out;
}

function arranged(me, home) {
  const all = available(me);
  const order = home?.order || [];
  const pos = (t) => { const i = order.indexOf(t.id); return i < 0 ? 1000 + all.indexOf(t) : i; };
  return all.map((t) => ({ ...t, title: home?.titles?.[t.id] || t.title, text: home?.texts?.[t.id] ?? t.text,
                           hidden: (home?.hidden || []).includes(t.id) })).sort((a, b) => pos(a) - pos(b));
}

function iconOf(t) {
  if (t.img) return `<span class="ico img" aria-hidden="true"><img src="${h(t.img)}" alt=""></span>`;
  if (t.icon && /^(https?:\/\/|\/)/.test(t.icon)) return `<span class="ico img" aria-hidden="true"><img src="${h(t.icon)}" alt=""></span>`;
  if (t.icon) return `<span class="ico emoji" aria-hidden="true">${h(t.icon)}</span>`;
  return `<span class="ico" aria-hidden="true">${t.link ? LINK : ICONS.tunnel}</span>`;
}

function tile(t) {
  return `<a href="${h(t.href)}" class="card lit opt"${t.ext ? ' target="_blank" rel="noopener"' : ""}>
    ${iconOf(t)}
    <div><h2>${h(t.title)}</h2>${t.text ? `<p>${h(t.text)}</p>` : ""}</div>
    <div class="go"><span>${h(t.foot || "")}</span>${t.ext ? ICONS.ext : ICONS.arrow}</div>
  </a>`;
}

function termixOffer(st) {
  const running = S.termixJob || st?.job?.state === "running";
  const failed = st?.job?.state === "error";
  return `<section class="card lit offer" id="termixOffer">
    <img class="offer-logo" src="/__gate/logos/termix.svg" alt="" width="52" height="52">
    <div class="grow">
      <h2>Add Termix?</h2>
      <p>SSH terminals, file manager and saved hosts in the browser, behind this same post-quantum login. One Docker container, only reachable through Aegis.</p>
      ${running ? `<p class="mono faint offer-log">${h(st?.job?.lines?.slice(-1)[0] || "starting…")}</p>` : ""}
      ${failed ? `<p class="mono offer-log err-msg">${h(st.job.error)}</p>` : ""}
    </div>
    <div class="offer-actions">
      <button class="btn primary" data-act="termix-install" ${running || (st && !st.docker) ? "disabled" : ""}>${running ? '<i class="spin"></i> Installing' : "Install Termix"}</button>
      <button class="btn ghost sm" data-act="termix-later">Not now</button>
    </div>
  </section>`;
}

async function render() {
  let me;
  try { me = S.me = await api("/__gate/api/me"); } catch (e) { opts.innerHTML = `<p class="muted">${h(e.message)}</p>`; return; }
  const home = me.home || {};
  $("#greet").textContent = home.greeting || "Unlocked";
  $("#tagline").textContent = home.tagline || "Where to?";
  document.body.dataset.bg = home.background || "grid";
  if (!document.querySelector(".upd-banner")) updateBanner(me, opts);
  if (!S.freshAsked) { S.freshAsked = true; freshUpdate(me, opts); }
  const tiles = arranged(me, home).filter((t) => !t.hidden);
  opts.innerHTML = tiles.length ? tiles.map(tile).join("")
    : `<div class="card lit empty-home"><p>Every tile is hidden. Use ${GEAR} to bring some back.</p></div>`;
  opts.classList.toggle("three", (home.columns || 2) === 3);
  document.querySelector(".home-in").classList.toggle("wide3", (home.columns || 2) === 3);

  let html = "";
  if (!me.pack.decided) {
    html += `<a class="card banner pack-banner" href="/__gate/welcome"><img src="/__gate/logos/aegis-burrow.svg" alt="" width="38" height="38">
      <div class="grow"><b>Finish setting up</b><span>Install the full pack (Selkies Forge, Termix, Burrow), pick parts of it, or say no thanks.</span></div>${ICONS.arrow}</a>`;
  }
  if (home.showBanners !== false) {
    let later = false;
    try { later = localStorage.getItem("aegis-termix-later") === "1"; } catch { /* private mode */ }
    if (!me.termix && (!later || S.termixJob) && me.pack.decided) {
      let st = null;
      try { st = await api("/__gate/api/termix"); } catch { /* unknown */ }
      if (st?.configured) { S.termixJob = false; return render(); }
      html += termixOffer(st);
      if (st?.job?.state === "running") setTimeout(render, 2000); else S.termixJob = false;
    }
    if (me.modules.burrow && !me.domain) {
      html += `<a class="card banner" href="/__gate/settings#domain"><span class="ico" aria-hidden="true">${ICONS.globe}</span>
        <div class="grow"><b>Use your own domain</b><span>Burrow's tunnels get random trycloudflare.com names until you link one. It takes a minute: authorize Cloudflare, pick a name.</span></div>${ICONS.arrow}</a>`;
    }
  }
  extra.innerHTML = html;
}

// ------------------------------------------------------------------ customize
function draft() {
  const me = S.me, home = me.home || {};
  return {
    greeting: home.greeting || "", tagline: home.tagline || "", columns: home.columns || 2, background: home.background || "grid",
    showBanners: home.showBanners !== false, links: (home.links || []).map((l) => ({ ...l })),
    tiles: arranged(me, home).map((t) => ({ id: t.id, title: t.title, text: t.text, hidden: t.hidden, link: !!t.link,
                                            base: available(me).find((x) => x.id === t.id) })),
  };
}

function panel() {
  const d = S.draft;
  const row = (t, i) => {
    const l = t.link ? d.links.find((x) => x.id === t.id) : null;
    return `<div class="cz-row${t.hidden ? " off" : ""}" data-i="${i}">
      <div class="cz-move"><button type="button" class="iconbtn" data-cz="up" ${i ? "" : "disabled"} aria-label="Move up">${UP}</button>
        <button type="button" class="iconbtn" data-cz="down" ${i < d.tiles.length - 1 ? "" : "disabled"} aria-label="Move down">${DOWN}</button></div>
      ${iconOf(t.base || { link: true, icon: l?.icon })}
      <div class="cz-fields">
        <input class="input" data-f="title" value="${h(t.title)}" maxlength="60" aria-label="Title">
        <input class="input sm" data-f="text" value="${h(t.text || "")}" maxlength="160" placeholder="Description" aria-label="Description">
        ${l ? `<div class="row"><input class="input sm mono" data-f="url" value="${h(l.url)}" placeholder="https://…" aria-label="Address">
              <input class="input sm cz-icon" data-f="icon" value="${h(l.icon || "")}" placeholder="🔗 or image URL" aria-label="Icon"></div>` : ""}
      </div>
      <div class="cz-acts">
        <button type="button" class="iconbtn" data-cz="hide" title="${t.hidden ? "Show" : "Hide"}" aria-label="${t.hidden ? "Show" : "Hide"}">${t.hidden ? EYEOFF : EYE}</button>
        ${l ? `<button type="button" class="iconbtn danger" data-cz="del" title="Remove" aria-label="Remove">${TRASH}</button>` : ""}
      </div>
    </div>`;
  };
  const seg = (name, val, choices) => `<div class="seg" data-seg="${name}">${choices.map(([v, l]) =>
    `<button type="button" data-v="${v}" class="${String(val) === String(v) ? "on" : ""}">${l}</button>`).join("")}</div>`;
  return `<div class="cz-head"><span class="cz-gear">${GEAR}</span><div><h2>Customize the dashboard</h2><p>Only you see this. Saved for everyone who signs in here.</p></div></div>
    <div class="row flexwrap">
      <label class="field grow"><span>Greeting</span><input class="input" id="czGreet" value="${h(d.greeting)}" placeholder="Unlocked" maxlength="60"></label>
      <label class="field grow"><span>Tagline</span><input class="input" id="czTag" value="${h(d.tagline)}" placeholder="Where to?" maxlength="80"></label>
    </div>
    <div class="cz-opts">
      <div class="field"><span>Columns</span>${seg("columns", d.columns, [[2, "Two"], [3, "Three"]])}</div>
      <div class="field"><span>Background</span>${seg("background", d.background, [["grid", "Grid"], ["glow", "Glow"], ["plain", "Plain"]])}</div>
      <label class="row cz-check"><span class="switch"><input type="checkbox" id="czBanners" ${d.showBanners ? "checked" : ""}><i></i></span><span>Suggestions under the tiles</span></label>
    </div>
    <div class="cz-k">Tiles <span class="faint">order, names, what shows</span></div>
    <div class="cz-list">${d.tiles.map(row).join("")}</div>
    <button type="button" class="btn sm" data-cz="add">${LINK} Add a link tile</button>
    <div class="modal-actions cz-foot">
      <a class="btn ghost sm" href="/__gate/settings">All settings</a><span class="grow"></span>
      <button type="button" class="btn ghost" data-cz="reset">Reset</button>
      <button type="button" class="btn ghost" data-act="close">Cancel</button>
      <button type="button" class="btn primary" data-cz="save">Save</button>
    </div>`;
}

function openPanel() {
  S.draft = draft();
  const scrim = document.createElement("div");
  scrim.className = "scrim";
  scrim.innerHTML = `<div class="card lit modal cz" role="dialog" aria-modal="true" aria-label="Customize the dashboard">${panel()}</div>`;
  scrim.addEventListener("mousedown", (e) => { if (e.target === scrim) closePanel(); });
  document.body.append(scrim);
  S.scrim = scrim;
}
function closePanel() { S.scrim?.remove(); S.scrim = null; S.draft = null; }
function repaint() { readInputs(); S.scrim.querySelector(".cz").innerHTML = panel(); }

function readInputs() {
  const d = S.draft, m = S.scrim;
  if (!d || !m) return;
  d.greeting = m.querySelector("#czGreet")?.value ?? d.greeting;
  d.tagline = m.querySelector("#czTag")?.value ?? d.tagline;
  d.showBanners = m.querySelector("#czBanners")?.checked ?? d.showBanners;
  m.querySelectorAll(".cz-row").forEach((r) => {
    const t = d.tiles[Number(r.dataset.i)];
    const v = (f) => r.querySelector(`[data-f="${f}"]`)?.value;
    t.title = v("title") ?? t.title; t.text = v("text") ?? t.text;
    if (t.link) { const l = d.links.find((x) => x.id === t.id); if (l) { l.url = v("url") ?? l.url; l.icon = v("icon") ?? l.icon; l.title = t.title; l.text = t.text; } }
  });
}

async function save() {
  readInputs();
  const d = S.draft;
  const titles = {}, texts = {};
  for (const t of d.tiles) {
    if (t.link) continue;
    if (t.base && t.title && t.title !== t.base.title) titles[t.id] = t.title;
    if (t.base && t.text !== t.base.text) texts[t.id] = t.text || " ";
  }
  const bad = d.links.find((l) => !/^(https?:\/\/\S+|\/\S*)$/.test(l.url || ""));
  if (bad) { toast(`"${bad.title}" needs an address (https://… or /path)`); return; }
  const home = { greeting: d.greeting, tagline: d.tagline, columns: d.columns, background: d.background, showBanners: d.showBanners,
                 order: d.tiles.map((t) => t.id), hidden: d.tiles.filter((t) => t.hidden).map((t) => t.id), titles, texts, links: d.links };
  try { await post("/__gate/api/prefs", { home }); closePanel(); toast("Dashboard saved"); render(); }
  catch (e) { toast(e.message); }
}

document.addEventListener("input", (e) => { if (e.target.closest(".cz")) readInputs(); });
document.addEventListener("click", async (e) => {
  const seg = e.target.closest("[data-seg] button");
  if (seg && S.draft) { const k = seg.parentElement.dataset.seg; S.draft[k] = k === "columns" ? Number(seg.dataset.v) : seg.dataset.v; repaint(); return; }
  const cz = e.target.closest("[data-cz]");
  if (cz && S.draft) {
    readInputs();
    const d = S.draft, i = Number(cz.closest(".cz-row")?.dataset.i);
    const act = cz.dataset.cz;
    if (act === "up" && i > 0) [d.tiles[i - 1], d.tiles[i]] = [d.tiles[i], d.tiles[i - 1]];
    else if (act === "down" && i < d.tiles.length - 1) [d.tiles[i + 1], d.tiles[i]] = [d.tiles[i], d.tiles[i + 1]];
    else if (act === "hide") d.tiles[i].hidden = !d.tiles[i].hidden;
    else if (act === "del") { const id = d.tiles[i].id; d.tiles.splice(i, 1); d.links = d.links.filter((l) => l.id !== id); }
    else if (act === "add") {
      const id = "link:" + Math.random().toString(36).slice(2, 10);
      d.links.push({ id, title: "New link", text: "", url: "https://", icon: "🔗" });
      d.tiles.push({ id, title: "New link", text: "", hidden: false, link: true });
    } else if (act === "reset") {
      if (!confirm("Put the dashboard back the way it came? Your link tiles are removed.")) return;
      await post("/__gate/api/prefs", { home: null }); closePanel(); toast("Dashboard reset"); render(); return;
    } else if (act === "save") { save(); return; }
    repaint();
    return;
  }
  const el = e.target.closest("[data-act]");
  if (!el) return;
  try {
    if (el.dataset.act === "close") closePanel();
    else if (el.dataset.act === "termix-install") { el.disabled = true; await post("/__gate/api/termix/install"); S.termixJob = true; toast("Installing Termix…"); render(); }
    else if (el.dataset.act === "termix-later") {
      try { localStorage.setItem("aegis-termix-later", "1"); } catch { /* private mode */ }
      $("#termixOffer")?.remove(); toast("You can add it later under Settings");
    }
  } catch (ex) { toast(ex.message); el.disabled = false; }
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && S.scrim) closePanel(); });

render().then(() => {
  // Settings → Customize the home page lands here
  if (new URLSearchParams(location.search).has("customize")) { history.replaceState(null, "", "/"); openPanel(); }
});
