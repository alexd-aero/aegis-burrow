// The Noxia tab: drive the VLESS + REALITY endpoint running on this machine
// (github.com/alexd-aero/noxia) through the gate's loopback proxy. Serve a
// port encrypted through Noxia, transfer a Burrow tunnel onto it, reroll the
// front, and — when it's switched on here — the browser-mode option.
//
// No inline handlers (strict CSP): one delegated listener, data-act attrs.
import { chrome } from "./common.js";

const $ = (s, el = document) => el.querySelector(s);
const app = $("#app");
const S = { me: null, data: null, tunnels: [], busy: false, timer: null, modal: null };
const h = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ICON = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 5.5V11c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V5.5z"/><path d="m9 12 2 2 4-4"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>',
  sync: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 0 1-14 5.3M4 12A8 8 0 0 1 18 6.7"/><path d="M18 2.5v4.5h-4.5M6 21.5V17h4.5"/></svg>',
  move: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14 0 18M12 3c-3 3.5-3 14 0 18"/></svg>',
};

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Gate": "1", ...(opts.headers || {}) } });
  if (r.status === 401) { location.href = "/__gate/login"; throw new Error("Signed out"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
function setLive(ok, text) { const el = $("#liveState"); if (el) el.innerHTML = `<i class="dot ${ok ? "ok" : "err"}"></i><span>${h(text)}</span>`; }
function toast(msg) { document.querySelectorAll(".toast").forEach((t) => t.remove()); const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; document.body.append(t); setTimeout(() => t.remove(), 2600); }

function statusCard(st) {
  const run = st.running ? "ok" : st.available ? "warn" : "err";
  const runText = st.running ? "running" : st.available ? "stopped" : "no xray";
  const f = st.front;
  return `<section class="card lit" style="border-color:rgba(124,92,255,.3)">
    <div class="t-top">
      <div class="fav lg" style="color:#a98bff">${ICON.shield}</div>
      <div class="grow"><div class="t-name">Noxia <span class="pill ${run}"><i class="dot ${run}"></i>${runText}</span> <span class="pill exp">experimental</span></div>
        <div class="t-url faint small">VLESS + REALITY · ${st.postQuantum ? "ML-DSA-65 post-quantum" : "classic"} · front <span class="mono">${h(f?.dest || "—")}</span>${f?.verified ? " ✓" : ""}</div></div>
      <div class="t-actions"><button class="btn sm" data-act="reroll">${ICON.sync} New front</button><button class="btn sm ghost" data-act="restart">Restart</button></div>
    </div>
    <div class="stats" style="margin-top:14px">
      <div class="card stat"><b>${st.running ? "live" : "—"}</b><span>endpoint</span><div class="sub mono">${h(st.listen || "")}:${h(String(st.port || ""))}</div></div>
      <div class="card stat"><b class="mono" style="font-size:13px">${h(st.publicHost || "set host")}</b><span>public address</span><div class="sub">clients connect here</div></div>
      <div class="card stat"><b>${(st.routes || []).length}</b><span>routes</span><div class="sub">ports served through Noxia</div></div>
      <div class="card stat"><b class="mono" style="font-size:12px">${h((st.xrayVersion || "—").replace("Xray ", ""))}</b><span>xray-core</span></div>
    </div>
    ${st.shareUri ? `<div style="margin-top:14px"><div class="row" style="display:flex;align-items:center;gap:8px"><b>Client link</b><span class="faint small">import into an Xray-core ≥26 client</span></div>
      <textarea id="nxUri" readonly spellcheck="false" style="width:100%;height:78px;margin-top:8px;background:#0d0f12;border:1px solid var(--line-2);border-radius:12px;color:#cfe0ff;font:12px var(--mono);padding:10px">${h(st.shareUri)}</textarea>
      <div style="margin-top:8px"><button class="btn sm primary" data-act="copy-uri">${ICON.copy} Copy link</button></div></div>`
      : `<div class="note-err small" style="margin-top:14px">No public address yet. Noxia's service sets it from its endpoint settings (NOXIA_RECORD / WAN port). The endpoint still runs locally.</div>`}
  </section>`;
}

function routesCard(st) {
  const routes = st.routes || [];
  return `<section class="card panel">
    <div class="t-top"><div class="grow"><h3 style="margin:0">Served through Noxia</h3>
      <p class="faint small" style="margin:4px 0 0">Each port here is reachable by a connected client, encrypted end to end. Everything else on this machine stays walled off.</p></div>
      <button class="btn sm primary" data-act="add">${ICON.plus} Add tunnel via Noxia</button></div>
    ${routes.length ? `<div class="pages-list" style="margin-top:12px">${routes.map((r) => `
      <div class="prow"><div class="fav" style="color:#a98bff">${ICON.shield}</div>
        <div class="grow"><div class="t-name">${h(r.label)}</div>
          <div class="t-url mono faint small">${h(r.host)}:${h(String(r.port))}${r.source === "transfer" ? " · transferred from Burrow" : ""}${r.browser ? " · browser mode" : ""}</div></div>
        <button class="btn sm ghost danger" data-act="route-rm" data-id="${h(r.id)}">Remove</button></div>`).join("")}</div>`
      : `<div class="pages-empty"><p class="muted small" style="margin-top:12px">Nothing served yet. <b>Add tunnel via Noxia</b> to pick a local port, or transfer a Burrow tunnel below.</p></div>`}
  </section>`;
}

function transferCard() {
  const ts = S.tunnels.filter((t) => !isSite(t));
  if (!ts.length) return "";
  const served = new Set((S.data?.status?.routes || []).map((r) => `${r.host}:${r.port}`));
  return `<section class="card panel"><h3 style="margin:0">Transfer a Burrow tunnel to Noxia</h3>
    <p class="faint small" style="margin:4px 0 12px">Move a tunnel's target onto Noxia encryption. You choose whether to also stop its public Cloudflare address.</p>
    <div class="pages-list">${ts.map((t) => {
      const on = served.has(`${t.targetHost}:${t.targetPort}`);
      return `<div class="prow"><div class="fav">${ICON.globe}</div>
        <div class="grow"><div class="t-name">${h(t.name || t.title || ("port " + t.port))}</div>
          <div class="t-url mono faint small">${h(t.targetHost)}:${h(String(t.targetPort))} ${t.enabled ? "" : "· paused"}</div></div>
        ${on ? '<span class="pill ok"><i class="dot ok"></i>on Noxia</span>'
          : `<button class="btn sm" data-act="transfer" data-port="${t.port}" data-host="${h(t.targetHost)}" data-tport="${t.targetPort}" data-name="${h(t.name || t.title || ("port " + t.port))}">${ICON.move} Transfer</button>`}</div>`;
    }).join("")}</div></section>`;
}
const isSite = (t) => t.kind === "site" || t.app === "burrow-pages";

function browserCard(view) {
  return `<section class="card panel">
    <div class="t-top"><div class="grow"><h3 style="margin:0">Browser mode</h3>
      <p class="faint small" style="margin:4px 0 0">When on, adding a tunnel can host a <b>server-side browser</b> for it — the page is fetched here and relayed encrypted, so the client browses fully through Noxia. Off by default.</p></div>
      <label class="switch" title="Browser mode"><input type="checkbox" data-act="browser-toggle" ${view.browserMode ? "checked" : ""}><i></i></label></div>
    ${view.browserMode ? `<p class="note small" style="margin-top:10px">On. The <b>Add tunnel via Noxia</b> dialog now offers “host a browser”. <span class="faint">(The hosted-browser backend is being ported from vpn-portal; the option is visible and records your choice.)</span></p>` : ""}
  </section>`;
}

function render() {
  if (!S.data) { app.innerHTML = `<div class="head"><div><h1>Noxia</h1><p>Loading…</p></div></div>`; return; }
  if (!S.data.present) {
    app.innerHTML = `<div class="head"><div><h1>Noxia</h1><p>A VLESS + REALITY tunnel, behind your keys.</p></div></div>
      <section class="card panel ab-none"><img src="/__gate/logos/noxia.svg" alt="" width="44" height="44">
        <div><h3>Noxia isn't running on this machine</h3>
        <p class="muted">Noxia is its own service (<span class="mono">github.com/alexd-aero/noxia</span>). Start it and this tab controls it — its web API on <span class="mono">127.0.0.1:7900</span> is reached only through this gate, never exposed.</p></div></section>`;
    return;
  }
  const st = S.data.status || {};
  app.innerHTML = `<div class="head"><div><h1>Noxia</h1><p>VLESS + REALITY · post-quantum · a random TLS front. Serve a port encrypted, behind your keys — not the public internet.</p></div></div>
    ${statusCard(st)}
    ${routesCard(st)}
    ${transferCard()}
    ${browserCard(S.data)}`;
}

// ---- actions ----
function openModal(html, onReady) {
  closeModal();
  const scrim = document.createElement("div");
  scrim.className = "scrim";
  scrim.innerHTML = `<div class="card lit modal" role="dialog" aria-modal="true">${html}</div>`;
  scrim.addEventListener("mousedown", (e) => { if (e.target === scrim) closeModal(); });
  document.body.append(scrim); S.modal = scrim;
  onReady?.(scrim.querySelector(".modal"));
}
function closeModal() { S.modal?.remove(); S.modal = null; }

function addForm(browserOn) {
  openModal(`<h2>Add a tunnel via Noxia</h2>
    <p class="muted">Pick a port on this machine. A connected client reaches it encrypted through Noxia; it is never exposed publicly.</p>
    <form id="nxAdd" autocomplete="off">
      <div class="d-two">
        <label class="field"><span>Host</span><input class="input mono" id="nxHost" value="127.0.0.1" spellcheck="false"></label>
        <label class="field"><span>Port</span><input class="input mono" id="nxPort" type="number" min="1" max="65535" placeholder="8787" autofocus></label>
      </div>
      <label class="field"><span>Label <span class="faint">(optional)</span></span><input class="input" id="nxLabel" maxlength="60" placeholder="e.g. Grafana"></label>
      ${browserOn ? `<label class="check" style="display:flex;gap:8px;align-items:center;margin:4px 0 6px"><input type="checkbox" id="nxBrowser"><span>Host a browser for it (browser mode)</span></label>` : ""}
      <div class="err-msg" id="nxErr"></div>
      <div class="modal-actions"><button type="button" class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="nxGo">${ICON.plus} Serve through Noxia</button></div>
    </form>`, (m) => {
    m.querySelector("#nxAdd").addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = m.querySelector("#nxErr"), go = m.querySelector("#nxGo");
      err.textContent = "";
      const body = { host: m.querySelector("#nxHost").value.trim() || "127.0.0.1", port: Number(m.querySelector("#nxPort").value),
                     label: m.querySelector("#nxLabel").value.trim() || undefined, browser: browserOn && m.querySelector("#nxBrowser")?.checked || undefined };
      try { go.disabled = true; go.textContent = "Adding…"; await api("/__gate/api/noxia/routes", { method: "POST", body: JSON.stringify(body) }); closeModal(); toast("Serving through Noxia"); await load(); }
      catch (ex) { err.textContent = ex.message; go.disabled = false; go.innerHTML = `${ICON.plus} Serve through Noxia`; }
    });
  });
}

async function doTransfer(b) {
  const label = b.dataset.name;
  try {
    await api("/__gate/api/noxia/routes", { method: "POST", body: JSON.stringify({ host: b.dataset.host, port: Number(b.dataset.tport), label, source: "transfer" }) });
    if (confirm(`"${label}" is now served through Noxia.\n\nAlso stop its public Cloudflare address, so it's reachable only via Noxia?`)) {
      await api(`/__gate/api/tunnels/${b.dataset.port}`, { method: "PATCH", body: JSON.stringify({ enabled: false }) }).catch(() => {});
      toast("Transferred; public tunnel stopped");
    } else toast("Transferred (public tunnel left on)");
    await load();
  } catch (e) { toast(e.message); }
}

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-act]"); if (!el) return;
  const act = el.dataset.act;
  try {
    if (act === "reroll") { el.disabled = true; S.data.status = await api("/__gate/api/noxia/reroll", { method: "POST", body: "{}" }); toast("New front: " + (S.data.status.front?.dest || "")); render(); }
    else if (act === "restart") { el.disabled = true; S.data.status = await api("/__gate/api/noxia/restart", { method: "POST", body: "{}" }); toast("Restarted"); render(); }
    else if (act === "copy-uri") { const t = $("#nxUri"); if (t) { await navigator.clipboard.writeText(t.value).catch(() => { t.select(); document.execCommand("copy"); }); toast("Link copied"); } }
    else if (act === "add") addForm(S.data.browserMode);
    else if (act === "route-rm") { el.disabled = true; await api(`/__gate/api/noxia/routes/${el.dataset.id}`, { method: "DELETE" }); toast("Removed"); await load(); }
    else if (act === "transfer") { el.disabled = true; await doTransfer(el); }
    else if (act === "browser-toggle") { const v = await api("/__gate/api/noxia/browser-mode", { method: "POST", body: JSON.stringify({ enabled: el.checked }) }); S.data.browserMode = v.browserMode; render(); }
  } catch (ex) { toast(ex.message); if (el) el.disabled = false; }
});

async function load() {
  try {
    S.data = await api("/__gate/api/noxia");
    S.tunnels = (await api("/__gate/api/tunnels").catch(() => ({ tunnels: [] }))).tunnels || [];
    setLive(true, S.data.present ? "live" : "no noxia");
    render();
  } catch (e) { setLive(false, "offline"); }
}

chrome("noxia").then((me) => { S.me = me; load(); S.timer = setInterval(load, 7000); });
