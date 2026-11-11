// Settings → Themes (Weft spec §12): what's in use, what's installed, adding
// one (a .zip, a link, a GitHub or GitLab repository), Discover (forks of the
// Weft repository with a .theme), and the screen you confirm on: the theme's
// previews, a live run of its pages in frames, its .stability check and the
// safety scan of its code. Nothing applies until you say so.
import { h, toast, ago } from "./common.js";

const TH = { tab: "installed", data: null, discover: null, discovering: false, busy: false, src: "", drag: false, err: "", rerender: () => {} };
const LEVEL = {
  stable: ["ok", "Stable"], aged: ["warn", "Proven on another version"], newer: ["warn", "Proven on a newer Aegis"], unproven: ["", "Not proven stable"],
  changed: ["err", "Changed since tested"], failed: ["err", "Failed its own test"], broken: ["err", ".stability damaged"],
};
const SAFE = { styles: ["ok", "Styles only"], clean: ["ok", "Code: nothing unusual"], review: ["warn", "Code: worth a look"], danger: ["err", "Code: be careful"] };
const I = {
  up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M7 9l5-5 5 5M5 20h14"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 5.5V11c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V5.5z"/></svg>',
  beaker: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3"/><path d="M7.5 14h9"/></svg>',
  star: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z"/></svg>',
  branch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="6" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 8v8M18 10c0 4-6 3-10 7"/></svg>',
};
async function call(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts, headers: { "X-Gate": "1", ...(opts.body && typeof opts.body === "string" ? { "Content-Type": "application/json" } : {}), ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), j);
  return j;
}
const badge = (map, level, extra = "") => { const [cls, label] = map[level] || ["", level]; return `<span class="pill ${cls} th-badge"${extra}>${label}</span>`; };

export async function loadThemes() {
  try { TH.data = await call("/__gate/api/themes"); } catch (e) { TH.err = e.message; }
  TH.rerender();
}
export function themesBody() {
  const d = TH.data;
  if (!d) return '<p class="muted"><i class="spin"></i> Loading…</p>';
  const act = d.themes.find((t) => t.active);
  const cur = act ? `<div class="th-cur"${act.accent ? ` style="--th-c:${h(act.accent)}"` : ""}>
      ${act.previews[0] ? `<img class="th-shot" src="${h(act.previews[0].url)}" alt="">` : '<div class="th-shot"></div>'}
      <div class="grow"><span class="faint small mono">IN USE</span><h3>${h(act.name)} <span class="mono faint">${h(act.version)}</span></h3>
        <p class="muted small">${h(act.description || "")}</p>
        <div class="row th-badges">${badge(LEVEL, act.stabilityNow.level, ` title="${h(act.stabilityNow.title)}"`)}${badge(SAFE, act.safety)}${act.author ? `<span class="faint small">by ${h(act.author)}</span>` : ""}</div></div>
      <div class="th-cur-acts">${act.backgrounds ? '<button type="button" class="btn sm" data-th="bg">Background…</button>' : ""}
        <button type="button" class="btn sm ghost" data-th="welcome" data-id="${h(act.id)}">Welcome again</button>
        <button type="button" class="btn sm ghost" data-th="off">Use the default look</button></div></div>`
    : `<div class="th-cur none"><div class="th-shot def"><span>Aa</span></div><div class="grow"><span class="faint small mono">IN USE</span><h3>Aegis's own look</h3>
        <p class="muted small">A theme gives the signed-in pages a new look. Add one below, or find one in Discover.</p></div></div>`;
  const tabs = `<div class="seg th-tabs" role="tablist">${[["installed", `Installed${d.themes.length ? ` (${d.themes.length})` : ""}`], ["add", "Add a theme"], ["discover", "Discover"]]
    .map(([k, l]) => `<button type="button" role="tab" data-th="tab" data-v="${k}" class="${TH.tab === k ? "on" : ""}" aria-selected="${TH.tab === k}">${l}</button>`).join("")}</div>`;
  let body = "";
  if (TH.tab === "installed") {
    body = d.themes.length ? `<div class="th-list">${d.themes.map((t) => `<div class="th-row${t.active ? " on" : ""}">
        ${t.previews[0] ? `<img class="th-thumb" src="${h(t.previews[0].url)}" alt="">` : '<div class="th-thumb"></div>'}
        <div class="grow"><b>${h(t.name)}</b> <span class="mono faint small">${h(t.version)}</span>${t.active ? ' <span class="pill ok">in use</span>' : ""}
          <div class="row th-badges">${badge(LEVEL, t.stabilityNow.level, ` title="${h(t.stabilityNow.title)}"`)}${badge(SAFE, t.safety)}
            <span class="faint small">${t.stylesOnly ? "styles" : t.pages.length ? `draws ${t.pages.join(", ")}` : "styles and scripts"} · added ${ago(t.installed)}${t.source?.display ? ` · from ${h(t.source.display.replace(/^https?:\/\//, "").slice(0, 60))}` : ""}</span></div></div>
        <div class="th-acts">${t.active ? "" : `<button type="button" class="btn sm primary" data-th="use" data-id="${h(t.id)}">Use it</button>`}
          ${t.canUpdate ? `<button type="button" class="btn sm" data-th="update" data-id="${h(t.id)}">Check for an update</button>` : ""}
          <button type="button" class="btn sm" data-th="stamp" data-id="${h(t.id)}" title="Runs its pages here and writes a .stability file">${I.beaker} Prove it stable</button>
          ${t.stabilityNow.level !== "unproven" ? `<a class="btn sm ghost" href="/__gate/api/themes/${h(t.id)}/stability" download=".stability">.stability</a>` : ""}
          ${t.hasPrevious ? `<button type="button" class="btn sm ghost" data-th="rollback" data-id="${h(t.id)}">Previous version</button>` : ""}
          <button type="button" class="btn sm ghost danger" data-th="remove" data-id="${h(t.id)}">Remove</button></div></div>`).join("")}</div>`
      : `<p class="muted small">No themes yet. <button type="button" class="link" data-th="tab" data-v="add">Add one</button> or <button type="button" class="link" data-th="tab" data-v="discover">discover one</button>.</p>`;
  } else if (TH.tab === "add") {
    body = `<label class="th-drop${TH.drag ? " drag" : ""}${TH.busy ? " busy" : ""}" id="thDrop">
        <input type="file" id="thFile" accept=".zip,.tgz,.gz,.tar,application/zip,application/gzip" hidden ${TH.busy ? "disabled" : ""}>
        ${TH.busy ? `<i class="spin"></i><b>${h(TH.busy)}</b>` : `${I.up}<b>Drop a theme's .zip here</b><span class="muted small">or choose one · archives inside archives are opened too</span>`}</label>
      <div class="th-or"><span>or a link</span></div>
      <form class="row th-src" id="thSrcForm" autocomplete="off">
        <input class="input grow mono" id="thSrc" value="${h(TH.src)}" spellcheck="false" placeholder="https://github.com/you/weft  ·  a GitLab repository  ·  https://…/theme.zip" ${TH.busy ? "disabled" : ""}>
        <button class="btn primary" ${TH.busy ? "disabled" : ""}>Look at it</button></form>
      ${TH.err ? `<p class="err-msg">${h(TH.err)}</p>` : ""}
      <p class="faint small th-fine">Nothing runs and nothing changes yet: Aegis unpacks it, checks its <span class="mono">.stability</span> file, scans its code, and shows you its previews and a live run of its pages. You confirm, or it goes.</p>`;
  } else {
    const D = TH.discover;
    const card = (c) => `<div class="th-card"${c.accent ? ` style="--th-c:${h(c.accent)}"` : ""}>
        <div class="th-card-shot">${c.previews[0] ? `<img src="${h(c.previews[0].url)}" alt="" loading="lazy">` : ""}${c.previews.length > 1 ? `<span class="th-more">+${c.previews.length - 1}</span>` : ""}</div>
        <div class="th-card-in"><div class="row"><b class="grow">${h(c.name)}</b>${c.official ? '<span class="pill ok">Weft</span>' : ""}</div>
          <span class="faint small">${h(c.author)} · ${h(c.version)}${c.stars ? ` · ${I.star} ${c.stars}` : ""}${c.updated ? ` · ${ago(Date.parse(c.updated))}` : ""}</span>
          <p class="muted small">${h(c.description || "No description.")}</p>
          <div class="row th-badges">${c.backgrounds ? '<span class="pill">backgrounds</span>' : ""}${c.requires ? `<span class="pill">${h(c.requires)}</span>` : ""}${c.license ? `<span class="pill">${h(c.license)}</span>` : ""}</div>
          <div class="row end"><a class="btn sm ghost" href="${h(c.source)}" target="_blank" rel="noopener">${I.branch} Source</a>
            <button type="button" class="btn sm primary" data-th="install" data-src="${h(c.source)}">Preview & install</button></div></div></div>`;
    body = !D ? `<p class="muted"><i class="spin"></i> Looking through the Weft repository's forks…</p>`
      : `<div class="row th-disc-top"><span class="faint small">${D.error ? h(D.error) : `${D.featured.length + D.community.length} themes · ${D.forks ?? 0} forks looked at · ${ago(D.at)}`}</span><span class="grow"></span>
          <button type="button" class="btn sm ghost" data-th="rediscover" ${TH.discovering ? "disabled" : ""}>${TH.discovering ? '<i class="spin"></i> Looking' : "Look again"}</button></div>
        ${D.featured.length ? `<h4 class="th-h4">From Weft</h4><div class="th-cards">${D.featured.map(card).join("")}</div>` : ""}
        <h4 class="th-h4">Made by people</h4>
        ${D.community.length ? `<div class="th-cards">${D.community.map(card).join("")}</div>` : '<p class="muted small">None yet.</p>'}
        <div class="th-howto"><b>Share yours here</b><p class="muted small">Fork <a class="link" href="https://github.com/alexd-aero/weft" target="_blank" rel="noopener">alexd-aero/weft</a>, put your theme in it with a <span class="mono">.theme</span> file at the top (Weft spec §12), add pictures of it for <span class="mono">"previews"</span>, and prove it stable (Installed → Prove it stable) so people see the green badge. Every Aegis finds it here within the hour.</p></div>`;
  }
  return `${cur}${tabs}<div class="th-pane">${body}</div>`;
}

export function wireThemes(rerender) {
  TH.rerender = rerender;
  if (!TH.data) loadThemes();
  if (TH.tab === "discover" && !TH.discover && !TH.discovering) discover(false);
  const drop = document.getElementById("thDrop");
  if (drop) {
    drop.addEventListener("dragover", (e) => { e.preventDefault(); if (!TH.drag) { TH.drag = true; drop.classList.add("drag"); } });
    drop.addEventListener("dragleave", () => { TH.drag = false; drop.classList.remove("drag"); });
    drop.addEventListener("drop", (e) => { e.preventDefault(); TH.drag = false; const f = e.dataTransfer.files?.[0]; if (f) upload(f); });
  }
  document.getElementById("thFile")?.addEventListener("change", (e) => { const f = e.target.files?.[0]; if (f) upload(f); });
  document.getElementById("thSrcForm")?.addEventListener("submit", (e) => { e.preventDefault(); const v = document.getElementById("thSrc").value.trim(); TH.src = v; if (v) inspect({ source: v }); });
  document.getElementById("thSrc")?.addEventListener("input", (e) => { TH.src = e.target.value; });
}
async function discover(fresh) {
  TH.discovering = true; TH.rerender();
  try { TH.discover = await call(`/__gate/api/themes/discover${fresh ? "?fresh=1" : ""}`); } catch (e) { TH.discover = { at: Date.now(), featured: [], community: [], error: e.message }; }
  TH.discovering = false; TH.rerender();
}
async function upload(file) {
  if (file.size > 200e6) { TH.err = "That file is larger than 200 MB."; return TH.rerender(); }
  TH.busy = `Opening ${file.name}…`; TH.err = ""; TH.rerender();
  try { report(await call(`/__gate/api/themes/inspect?name=${encodeURIComponent(file.name)}`, { method: "POST", body: file, headers: { "Content-Type": "application/octet-stream" } })); }
  catch (e) { TH.err = e.message; }
  TH.busy = false; TH.rerender();
}
async function inspect(body) {
  TH.busy = "Fetching it and looking inside…"; TH.err = ""; TH.rerender();
  try { report(await call("/__gate/api/themes/inspect", { method: "POST", body: JSON.stringify(body) })); }
  catch (e) { TH.err = e.message; if (TH.tab !== "add") { TH.tab = "add"; } toast(e.message); }
  TH.busy = false; TH.rerender();
}

document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-th]");
  if (!b) return;
  const act = b.dataset.th, id = b.dataset.id;
  try {
    if (act === "tab") { TH.tab = b.dataset.v; TH.err = ""; TH.rerender(); if (TH.tab === "discover" && !TH.discover) discover(false); }
    else if (act === "rediscover") discover(true);
    else if (act === "install") inspect({ source: b.dataset.src });
    else if (act === "use") { b.disabled = true; TH.data = await call("/__gate/api/themes/use", { method: "POST", body: JSON.stringify({ id }) }); location.reload(); }
    else if (act === "off") { if (!confirm("Go back to Aegis's own look? Your themes stay installed.")) return; await call("/__gate/api/themes/use", { method: "POST", body: JSON.stringify({ id: null }) }); location.reload(); }
    else if (act === "remove") {
      const t = TH.data.themes.find((x) => x.id === id);
      if (!confirm(`Remove ${t?.name || id}? Its files are deleted from this machine.${t?.active ? " The default look comes back." : ""}`)) return;
      TH.data = await call(`/__gate/api/themes/${id}`, { method: "DELETE" });
      if (t?.active) location.reload(); else TH.rerender();
    } else if (act === "rollback") {
      if (!confirm("Go back to the version before this one?")) return;
      await call(`/__gate/api/themes/${id}/rollback`, { method: "POST", body: "{}" }); location.reload();
    } else if (act === "update") { b.disabled = true; b.textContent = "Checking…"; report(await call(`/__gate/api/themes/${id}/update`, { method: "POST", body: "{}" })); TH.rerender(); }
    else if (act === "welcome") { await call(`/__gate/api/themes/${id}/welcome`, { method: "POST", body: "{}" }); location.reload(); }
    else if (act === "bg") window.WeftHost?.pickBackground();
    else if (act === "stamp") prove(id);
  } catch (ex) { toast(ex.message); b.disabled = false; }
});

// ---------------------------------------------------------------- the confirm screen
const RUN_PAGES = [["home", "Home"], ["tunnels", "Burrow"], ["settings", "Settings"]];
function modal(cls, html) {
  const scrim = document.createElement("div");
  scrim.className = "scrim th-scrim";
  scrim.innerHTML = `<div class="card lit modal ${cls}" role="dialog" aria-modal="true">${html}</div>`;
  document.body.append(scrim);
  return scrim;
}
// several themes in one upload: which one?
function choose(r) {
  const sc = modal("th-choose", `<h2>${r.choose.length} themes in there</h2><p>Which one do you want to look at?</p>
    <div class="th-list">${r.choose.map((c) => `<button type="button" class="th-row pick" data-i="${c.i}"><div class="grow"><b>${h(c.name)}</b> <span class="mono faint small">${h(c.version)}</span><div class="faint small mono">${h(c.path)}</div></div></button>`).join("")}</div>
    <div class="modal-actions"><button type="button" class="btn ghost" data-x>Cancel</button></div>`);
  sc.addEventListener("click", async (e) => {
    if (e.target === sc || e.target.closest("[data-x]")) { sc.remove(); call(`/__gate/api/themes/staged/${r.token}`, { method: "DELETE" }).catch(() => {}); return; }
    const p = e.target.closest("[data-i]");
    if (!p) return;
    sc.remove();
    try { report(await call("/__gate/api/themes/inspect", { method: "POST", body: JSON.stringify({ token: r.token, pick: Number(p.dataset.i) }) })); } catch (ex) { toast(ex.message); }
  });
}
function report(r) {
  if (r.choose) return choose(r);
  if (!r.ok && !r.manifest) {
    const sc = modal("th-report bad", `<h2>That can't be used as a theme</h2><ul class="th-errs">${r.errors.map((x) => `<li>${h(x)}</li>`).join("")}</ul>
      <p class="faint small">The rules are in the Weft spec, §12 (github.com/alexd-aero/weft).</p><div class="modal-actions"><button type="button" class="btn primary" data-x>Close</button></div>`);
    sc.addEventListener("click", (e) => { if (e.target === sc || e.target.closest("[data-x]")) { sc.remove(); call(`/__gate/api/themes/staged/${r.token}`, { method: "DELETE" }).catch(() => {}); } });
    return;
  }
  const m = r.manifest, st = r.stability, sf = r.safety;
  const R = { slide: 0, page: "home", runs: {}, looked: false, trust: false, applying: false };
  const sc = modal("th-report", "");
  const box = sc.querySelector(".modal");
  if (m.accent) box.style.setProperty("--th-c", m.accent);
  const frames = document.createElement("div");
  const paint = () => {
    const runs = RUN_PAGES.map(([p, label]) => {
      const x = R.runs[p];
      return `<button type="button" class="th-ptab${R.page === p ? " on" : ""}" data-thpage="${p}">${label}
        ${!x ? '<i class="spin sm"></i>' : x.timeout ? '<span class="pill warn">no answer</span>' : x.errors ? `<span class="pill err">${x.errors} error${x.errors === 1 ? "" : "s"}</span>` : x.ok ? `<span class="pill ok">✓ ${x.ms} ms</span>` : '<span class="pill warn">blank</span>'}</button>`;
    }).join("");
    const done = RUN_PAGES.every(([p]) => R.runs[p]);
    const errs = RUN_PAGES.reduce((a, [p]) => a + (R.runs[p]?.errors || 0), 0);
    const findings = sf.findings.filter((f) => f.level !== "info" || sf.level === "styles").concat(sf.findings.filter((f) => f.level === "info" && sf.level !== "styles").slice(0, 4));
    if (!box.querySelector("#thFrameBox")) {
      box.innerHTML = `<div id="thTop"></div><div class="th-body"><div class="th-left"><div id="thShots"></div>
        <div class="th-live"><div id="thLiveHead"></div><div class="th-frame" id="thFrameBox"></div>
          <p class="faint small">This is the real dashboard with the theme, only inside this frame. It's the theme's live stability run: what the core host script caught on each page.</p></div></div>
        <div class="th-right" id="thRight"></div></div><div class="th-foot" id="thFoot"></div>`;
      box.querySelector("#thFrameBox").append(frames);
    }
    const set = (id, html) => { box.querySelector("#" + id).innerHTML = html; };
    set("thTop", `<div class="th-top"><div class="grow"><span class="faint small mono">${r.installed ? (r.installed.newer > 0 ? `UPDATE · ${h(r.installed.version)} → ${h(m.version)}` : r.installed.newer < 0 ? `OLDER THAN YOURS (${h(r.installed.version)})` : "SAME VERSION AS YOURS") : "NEW THEME"}</span>
        <h2>${h(m.name)} <span class="mono faint">${h(m.version)}</span></h2>
        <p class="muted">${h(m.description || "")}</p>
        <span class="faint small">${m.author ? `by ${h(m.author)} · ` : ""}${m.license ? `${h(m.license)} · ` : ""}${h(r.source?.display || "")}${m.homepage ? ` · <a class="link" href="${h(m.homepage)}" target="_blank" rel="noopener">homepage</a>` : ""}</span></div>
        <button type="button" class="btn icon ghost" data-x aria-label="Close">✕</button></div>`);
    set("thShots", `<div class="th-shots">${m.previews.map((p, i) => `<img src="${h(p.url)}" alt="${h(p.caption)}" class="${i === R.slide ? "on" : ""}">`).join("")}
            ${m.previews.length > 1 ? `<div class="th-dots">${m.previews.map((p, i) => `<button type="button" class="${i === R.slide ? "on" : ""}" data-slide="${i}">${h(p.caption || i + 1)}</button>`).join("")}</div>` : ""}</div>`);
    set("thLiveHead", `<div class="row"><b class="grow">Live, on this dashboard</b><span class="faint small">${done ? (errs ? `${errs} error${errs === 1 ? "" : "s"}` : "every page drew, no errors") : "running its pages…"}</span></div>
            <div class="th-ptabs">${runs}</div>`);
    set("thRight", `<div class="th-box"><div class="row">${I.beaker}<b class="grow">Stability</b>${badge(LEVEL, st.level)}</div><p class="small"><b>${h(st.title)}</b></p>
            <ul class="th-lines">${(st.lines || []).slice(0, 9).map((l) => `<li>${h(l)}</li>`).join("")}</ul>
            ${st.made ? `<p class="faint small">Made ${h(st.made.slice(0, 10))}${st.by ? ` by ${h(st.by)}` : ""}</p>` : ""}</div>
          <div class="th-box"><div class="row">${I.shield}<b class="grow">Safety scan</b>${badge(SAFE, sf.level)}</div>
            <ul class="th-finds">${findings.map((f) => `<li class="${f.level}"><span>${h(f.what)}</span>${f.file ? `<span class="mono faint">${h(f.file)}${f.detail ? ` · ${h(f.detail)}` : ""}</span>` : ""}</li>`).join("") || '<li class="ok"><span>Nothing to point out.</span></li>'}</ul>
            ${sf.level !== "styles" ? '<p class="faint small">A theme with scripts runs inside your dashboard, signed in as you. Install ones you trust.</p>' : ""}</div>
          <div class="th-box"><b>What it changes</b>
            <p class="small muted">${r.files.stylesOnly ? `Only how things look (styles${r.files.layered ? ", on top of Aegis's own" : ""}).` : r.files.pages.length ? `Draws ${r.files.pages.join(", ")}.` : "Styles and scripts."} ${r.files.replaces.length} of the dashboard's files, ${r.files.assets} of its own, ${(r.files.bytes / 1048576).toFixed(1)} MB in all.
              ${m.backgrounds ? ` Has backgrounds${m.backgrounds.recommended.length ? ` (${m.backgrounds.recommended.length} picks to start with)` : ""}.` : ""}${m.onboarding.length ? ` A ${m.onboarding.length}-step welcome.` : ""}</p>
            ${r.files.ignored.length ? `<p class="faint small">Left out: ${r.files.ignored.slice(0, 4).map((f) => `${h(f.path)} (${h(f.why)})`).join("; ")}</p>` : ""}
            <p class="faint small">Never touched: the sign-in pages. Settings → Themes → Use the default look undoes it, and so does <span class="mono">/__gate/theme-off</span>.</p></div>
          ${r.errors.length ? `<div class="th-box bad"><b>It can't be applied</b><ul class="th-errs">${r.errors.map((x) => `<li>${h(x)}</li>`).join("")}</ul></div>` : ""}
          ${r.warnings.length ? `<div class="th-box"><ul class="th-lines">${r.warnings.map((x) => `<li>${h(x)}</li>`).join("")}</ul></div>` : ""}`);
    set("thFoot", `<label class="check"><input type="checkbox" id="thLooked" ${R.looked ? "checked" : ""}> I looked at the previews and the live run</label>
        ${sf.level === "danger" ? `<label class="check"><input type="checkbox" id="thTrust" ${R.trust ? "checked" : ""}> I trust ${h(m.author || "its author")}, even with what the scan found</label>` : ""}
        <span class="grow"></span><button type="button" class="btn ghost" data-x>Cancel</button>
        <button type="button" class="btn primary" data-apply ${!r.ok || !R.looked || (sf.level === "danger" && !R.trust) || R.applying ? "disabled" : ""}>${R.applying ? '<i class="spin"></i> Applying' : r.installed ? "Apply this version" : "Apply theme"}</button>`);
    fit();
  };
  // the live run: one page at a time, each in a frame, the core host script reports back
  const order = RUN_PAGES.map(([p]) => p);
  const made = {};
  const load = (p) => {
    if (made[p]) return;
    const f = document.createElement("iframe");
    f.title = `${m.name}: ${p}`; f.loading = "eager"; f.dataset.page = p;
    f.src = `${r.preview}page/${p}`;
    f.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms");
    made[p] = f; frames.append(f);
    R.timer = setTimeout(() => { if (!R.runs[p]) { R.runs[p] = { timeout: true, errors: 0 }; paint(); next(); } }, 30000);
    show();
  };
  const show = () => { for (const f of frames.children) f.classList.toggle("on", f.dataset.page === R.page); };
  const next = () => { const p = order.find((x) => !made[x]); if (p) load(p); };
  const fit = () => { const w = frames.parentElement?.clientWidth || 600; frames.style.setProperty("--k", (w / 1280).toFixed(4)); };
  const onMsg = (e) => {
    if (e.origin !== location.origin || e.data?.type !== "weft-theme-run") return;
    const p = Object.keys(made).find((k) => made[k].contentWindow === e.source);
    if (!p || R.runs[p]) return;
    clearTimeout(R.timer);
    R.runs[p] = e.data;
    paint(); next();
  };
  addEventListener("message", onMsg);
  addEventListener("resize", fit);
  const close = (keep) => { removeEventListener("message", onMsg); removeEventListener("resize", fit); clearTimeout(R.timer); sc.remove(); if (!keep) call(`/__gate/api/themes/staged/${r.token}`, { method: "DELETE" }).catch(() => {}); };
  sc.addEventListener("click", async (e) => {
    if (e.target === sc || e.target.closest("[data-x]")) return close(false);
    const s = e.target.closest("[data-slide]"); if (s) { R.slide = Number(s.dataset.slide); return paint(); }
    const pt = e.target.closest("button[data-thpage]"); if (pt) { R.page = pt.dataset.thpage; load(R.page); show(); return paint(); }
    if (e.target.closest("[data-apply]")) {
      R.applying = true; paint();
      try { await call("/__gate/api/themes/apply", { method: "POST", body: JSON.stringify({ token: r.token, confirm: true, trust: R.trust }) }); close(true); toast(`${m.name} applied`); setTimeout(() => location.reload(), 350); }
      catch (ex) { R.applying = false; paint(); toast(ex.message); }
    }
  });
  sc.addEventListener("change", (e) => { if (e.target.id === "thLooked") { R.looked = e.target.checked; paint(); } if (e.target.id === "thTrust") { R.trust = e.target.checked; paint(); } });
  paint();
  load("home");
}

// ---------------------------------------------------------------- proving an installed theme stable
function prove(id) {
  const t = TH.data.themes.find((x) => x.id === id);
  const P = { runs: {}, frames: {}, text: null, err: null, busy: false };
  const sc = modal("th-prove", "");
  const box = sc.querySelector(".modal");
  const hidden = document.createElement("div");
  hidden.className = "th-hidden-frames";
  sc.append(hidden);
  const paint = () => {
    const done = RUN_PAGES.every(([p]) => P.runs[p]);
    box.innerHTML = `<h2>${I.beaker} Prove ${h(t.name)} stable</h2>
      <p>Aegis loads each of its pages here, with the core host script watching for errors, checks its files and code, and writes a <span class="mono">.stability</span> file with the result and the fingerprint of every file. Ship that file with the theme: anyone installing it sees it was proven on Aegis × Burrow, and that nothing changed since.</p>
      <ul class="th-lines run">${RUN_PAGES.map(([p, l]) => { const x = P.runs[p]; return `<li>${x ? (x.errors ? "✗" : x.ok ? "✓" : "?") : '<i class="spin sm"></i>'} ${l}${x ? ` · ${x.timeout ? "no answer" : `${x.errors} errors · ${x.ms} ms${x.ok ? "" : " · drew nothing"}`}` : " · loading…"}${x?.list?.length ? `<div class="mono faint small">${x.list.map(h).join("<br>")}</div>` : ""}</li>`; }).join("")}</ul>
      ${P.err ? `<p class="err-msg">${h(P.err)}</p>` : ""}
      ${P.text ? `<pre class="th-pre">${h(P.text)}</pre>` : ""}
      <div class="modal-actions">${P.text ? `<a class="btn" href="/__gate/api/themes/${h(id)}/stability" download=".stability">Download .stability</a>` : ""}
        <button type="button" class="btn ${P.text ? "primary" : "ghost"}" data-x>${P.text ? "Done" : "Cancel"}</button>
        ${P.text ? "" : `<button type="button" class="btn primary" data-go ${!done || P.busy ? "disabled" : ""}>${P.busy ? '<i class="spin"></i> Writing' : "Write .stability"}</button>`}</div>`;
  };
  const onMsg = (e) => {
    if (e.origin !== location.origin || e.data?.type !== "weft-theme-run") return;
    const p = Object.keys(P.frames).find((k) => P.frames[k].contentWindow === e.source);
    if (!p || P.runs[p]) return;
    P.runs[p] = e.data; paint(); next();
  };
  const next = () => {
    const p = RUN_PAGES.map(([x]) => x).find((x) => !P.frames[x]);
    if (!p) return;
    const f = document.createElement("iframe");
    f.src = `/__gate/theme-preview/i-${id}/page/${p}`;
    f.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms");
    P.frames[p] = f; hidden.append(f);
    setTimeout(() => { if (!P.runs[p]) { P.runs[p] = { timeout: true, errors: 0, ok: false, ms: 30000 }; paint(); next(); } }, 30000);
  };
  addEventListener("message", onMsg);
  sc.addEventListener("click", async (e) => {
    if (e.target === sc || e.target.closest("[data-x]")) { removeEventListener("message", onMsg); sc.remove(); if (P.text) loadThemes(); return; }
    if (e.target.closest("[data-go]")) {
      P.busy = true; P.err = null; paint();
      try { const live = RUN_PAGES.map(([p]) => ({ page: p, ...P.runs[p] })); P.text = (await call(`/__gate/api/themes/${id}/stamp`, { method: "POST", body: JSON.stringify({ live }) })).text; }
      catch (ex) { P.err = ex.message; }
      P.busy = false; paint();
    }
  });
  paint(); next();
}
