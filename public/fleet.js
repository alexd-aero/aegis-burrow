// Machine management: the Machines tab under Burrow.
//
// A canvas like Bulwark's patterns graph - this machine in the middle, every
// linked machine around it, drag to move, scroll to zoom - and a panel for
// whichever one you click: what it is made of, how loaded it is, what runs on
// it, and everything you can do to it from here.
//
// No inline handlers (strict CSP): the tab's own clicks come through
// tunnels.js's one delegated listener and land in click() below; the canvas
// wires its own pointer events when it is drawn.

const H = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtB = (b) => { if (!b) return "–"; const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(4, Math.floor(Math.log(b) / Math.log(1024))); return (b / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i]; };
const ago = (t) => { if (!t) return "never"; const s = Math.max(0, (Date.now() - t) / 1000); return s < 5 ? "now" : s < 60 ? Math.floor(s) + "s ago" : s < 3600 ? Math.floor(s / 60) + "m ago" : s < 86400 ? Math.floor(s / 3600) + "h ago" : Math.floor(s / 86400) + "d ago"; };
const dur = (s) => { if (!s) return "–"; const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600); return d ? `${d}d ${h}h` : h ? `${h}h ${Math.floor((s % 3600) / 60)}m` : `${Math.floor(s / 60)}m`; };
const pct = (a, b) => (b ? Math.max(0, Math.min(100, Math.round((a / b) * 100))) : 0);

const SVG = (d, w = 24) => `<svg viewBox="0 0 24 24" width="${w}" height="${w}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const I = {
  machine: SVG('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'),
  hub: SVG('<path d="M12 3 5 6v5.5c0 4.4 2.9 8.2 7 9.5 4.1-1.3 7-5.1 7-9.5V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>'),
  plus: SVG('<path d="M12 5v14M5 12h14"/>'),
  link: SVG('<path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/>'),
  term: SVG('<path d="m5 8 4 4-4 4M12 16h7"/>'),
  swap: SVG('<path d="M7 7h13l-3-3M17 17H4l3 3"/>'),
  copy: SVG('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>'),
  trash: SVG('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>'),
  refresh: SVG('<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 4v5h-5"/>'),
  shield: SVG('<path d="M12 3 5 5.5V11c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V5.5z"/>'),
  box: SVG('<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/>'),
  ext: SVG('<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>'),
  close: SVG('<path d="M6 6l12 12M18 6 6 18"/>'),
  fit: SVG('<rect x="3" y="5" width="18" height="14" rx="2.5"/><circle cx="12" cy="12" r="2.5"/>'),
  zin: SVG('<path d="M12 5v14M5 12h14"/>'), zout: SVG('<path d="M5 12h14"/>'),
};
const LOGOS = { "aegis-burrow": "/__gate/logos/aegis-burrow.svg", "selkies-forge": "/__gate/logos/forge.svg",
               bulwark: "/__gate/logos/bulwark.svg", termix: "/__gate/logos/termix.svg" };
// an addon's program ("<addon>:<program>") wears its addon's logo
const LOGO = new Proxy(LOGOS, { get: (o, id) => o[id] || (typeof id === "string" && /^[a-z0-9-]+:[a-z0-9-]+$/.test(id) ? `/__gate/api/addons/${id.split(":")[0]}/image` : undefined) });

// The tab's own state. `data` is the last /__gate/api/fleet.
export const FS = { data: null, sel: null, at: 0, link: null, pollTimer: null, fitKey: null,
                    pan: { x: 0, y: 0, k: 1 }, moved: new Map() };

let X = null;        // the bits tunnels.js lends us: api, toast, openModal, closeModal, render, jobRun
export function init(host) { X = host; }

export const machines = () => FS.data?.machines || [];
const selected = () => machines().find((m) => m.id === FS.sel) || null;
const catalog = () => FS.data?.catalog || [];
const appName = (id) => catalog().find((c) => c.id === id)?.name || id;

export async function load(fresh) {
  const d = await X.api("/__gate/api/fleet");
  FS.data = d; FS.at = Date.now();
  if (FS.sel && !machines().some((m) => m.id === FS.sel)) FS.sel = null;
  if (fresh) FS.moved.clear();
  return d;
}

// ------------------------------------------------------------------ the tab
export function render(app, head) {
  const d = FS.data;
  if (!d) { app.innerHTML = `<div class="head"><div><h1>Machines</h1><p>Loading…</p></div></div>${head}`; return; }
  if (!d.enabled) {
    app.innerHTML = `<div class="head"><div><h1>Machines</h1><p>Off. One command links another machine you own to this one.</p></div></div>${head}
      <section class="card lit fl-empty">
        <div class="fl-hero">${I.machine}</div>
        <h2>Run the whole set of machines from here</h2>
        <p>Switch machine management on and Aegis makes itself one SSH key. You run one command on the other
           machine; from then on this dashboard can see what it is made of and what runs on it, install apps on
           it, move an app and its data between the two, and keep a copy of this gate there that takes over if
           this host goes down.</p>
        <p class="muted">It stays off until you switch it on, and nothing reaches out until a machine is linked.</p>
        <a class="btn primary" href="/__gate/settings#modules">Settings → Modules</a>
      </section>`;
    return;
  }
  const t = d.takeover;
  app.innerHTML = `
    <div class="head">
      <div><h1>Machines</h1><p>${d.machines.length
        ? `This machine and ${d.machines.length} linked ${d.machines.length === 1 ? "one" : "ones"}. Click one to see what it is made of and what runs on it.`
        : "Nothing is linked yet. One command on another machine is all it takes."}</p></div>
      <div class="spacer"></div>
      <button class="btn ghost" data-act="fl-manual">Add by hand</button>
      <button class="btn primary" data-act="fl-link">${I.plus} Link a machine</button>
    </div>
    ${head}
    ${t && !t.handedBack ? takeoverCard(t) : ""}
    <div class="fl-wrap">
      <div>
        <div class="fl-graph card lit" id="flGraph"></div>
        <div class="fl-cards" id="flCards"></div>
      </div>
      ${panel()}
    </div>`;
  drawGraph(app.querySelector("#flGraph"), app.querySelector("#flCards"));
}

function takeoverCard(t) {
  return `<section class="card lit fl-takeover">
    <h2>${I.shield} This is the standby copy</h2>
    <p><b>${H(t.main)}</b> stopped answering, so this machine started its copy of the gate. ${H(t.reason)}.</p>
    <p>${t.mainReachable
      ? `That host is answering on SSH, so this one is running the restart script on it${t.attempts ? ` — ${t.attempts} ${t.attempts === 1 ? "try" : "tries"} so far` : ""}.`
      : `That host is not answering at all, so there is nothing to start on it yet. This one keeps checking, and runs the restart script the moment it comes back.`}</p>
    <p class="muted">Everything here is this gate's own copy: the same login, the same domain, the same tunnels.</p>
  </section>`;
}

// ------------------------------------------------------------------ the graph
// This machine in the middle, the rest on a ring around it. Drag the canvas
// to move, drag a card to place it, scroll to zoom.
const NW = 230, NH = 92, GAP = 20, COL = 110;

// This machine in the middle, the rest in a column either side of it, so
// nothing ever lands off the canvas however many there are.
function layout(w, h) {
  const list = machines();
  const cx = w / 2 - NW / 2, cy = h / 2 - NH / 2;
  const out = [{ id: "self", hub: true, x: cx, y: cy }];
  const sides = [[], []];
  list.forEach((m, i) => sides[i % 2].push(m));
  sides.forEach((side, s) => {
    const x = s === 0 ? cx + NW + COL : cx - NW - COL;
    const span = side.length * NH + (side.length - 1) * GAP;
    side.forEach((m, i) => {
      const moved = FS.moved.get(m.id);
      out.push({ id: m.id, m, x: moved ? moved.x : x, y: moved ? moved.y : cy + NH / 2 - span / 2 + i * (NH + GAP) });
    });
  });
  return out;
}
// Tall enough for the longest column, never taller than the window likes.
const canvasHeight = () => {
  const rows = Math.ceil(machines().length / 2);
  return Math.max(360, Math.min(640, rows * (NH + GAP) + 110));
};

// The canvas, and - for a narrow screen, where a canvas is no use - the same
// machines as a plain list. CSS shows one or the other.
function drawGraph(el, cards) {
  if (!el) return;
  const w = Math.max(640, el.clientWidth || 900), h = canvasHeight();
  const nodes = layout(w, h);
  if (cards) cards.innerHTML = nodes.map(nodeCard).join("");
  const by = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const edges = nodes.filter((n) => !n.hub).map((n) => {
    const a = by.self, b = n;
    const x1 = a.x + NW / 2, y1 = a.y + NH / 2, x2 = b.x + NW / 2, y2 = b.y + NH / 2;
    const mx = (x1 + x2) / 2;
    return `<path class="fl-edge ${n.m.up ? "on" : "off"}${n.m.standby ? " standby" : ""}" d="M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"/>`;
  }).join("");
  el.innerHTML = `
    <div class="fl-canvas" tabindex="0" style="height:${h}px" aria-label="Your machines. Drag to move, scroll to zoom.">
      <div class="fl-world">
        <svg class="fl-edges" width="${w * 2}" height="${h * 2}" aria-hidden="true">${edges}</svg>
        <div class="fl-nodes">${nodes.map(nodeCard).join("")}</div>
      </div>
      <div class="fl-tools" role="toolbar" aria-label="Canvas">
        <button type="button" data-fl="in" title="Zoom in" aria-label="Zoom in">${I.zin}</button>
        <button type="button" data-fl="out" title="Zoom out" aria-label="Zoom out">${I.zout}</button>
        <button type="button" data-fl="fit" title="Fit" aria-label="Fit">${I.fit}</button>
        <span class="fl-zoom">100%</span>
      </div>
      ${machines().length ? '<div class="fl-hint">drag to move \u00b7 scroll to zoom \u00b7 click a machine</div>'
        : `<div class="fl-none"><p>Only this machine so far.</p>
             <button class="btn sm primary" data-act="fl-link">${I.plus} Link one</button></div>`}
    </div>`;
  wireCanvas(el, by);
  // Fit the first time, and whenever the shape of the thing changes - but
  // never under someone who has just dragged or zoomed it themselves.
  const key = `${nodes.length}:${el.clientWidth}:${[...FS.moved.keys()].sort().join()}`;
  if (FS.fitKey !== key) { FS.fitKey = key; fit(el, nodes); }
  applyPan(el);
}

// Everything in view, centred, never magnified past life size.
function fit(el, nodes) {
  const canvas = el.querySelector(".fl-canvas");
  const cw = canvas.clientWidth || 900, ch = canvas.clientHeight || 420;
  const x0 = Math.min(...nodes.map((n) => n.x)), x1 = Math.max(...nodes.map((n) => n.x)) + NW;
  const y0 = Math.min(...nodes.map((n) => n.y)), y1 = Math.max(...nodes.map((n) => n.y)) + NH;
  const k = Math.max(0.4, Math.min(1, (cw - 34) / (x1 - x0), (ch - 34) / (y1 - y0)));
  FS.pan = { k, x: (cw - (x1 - x0) * k) / 2 - x0 * k, y: (ch - (y1 - y0) * k) / 2 - y0 * k };
}

function nodeCard(n) {
  if (n.hub) {
    const d = FS.data;
    return `<article class="fl-node hub" data-id="self" style="left:${n.x}px;top:${n.y}px">
      <div class="fl-ico">${I.hub}</div>
      <div class="fl-body"><b>${H(d.hub.name)}</b><span class="fl-sub">this machine · ${H(d.hub.hostname)}</span>
        <div class="fl-apps">${(d.here || []).map(chip).join("")}</div></div>
    </article>`;
  }
  const m = n.m;
  const u = m.usage || {};
  const cpu = u.load != null && u.cores ? Math.min(100, Math.round((u.load / u.cores) * 100)) : null;
  return `<article class="fl-node${FS.sel === m.id ? " on" : ""}${m.up ? "" : " down"}" data-id="${H(m.id)}" data-act="fl-pick" tabindex="0" role="link" style="left:${n.x}px;top:${n.y}px">
    <div class="fl-ico">${I.machine}</div>
    <div class="fl-body">
      <b>${H(m.name)}${m.standby ? `<span class="fl-tag">standby</span>` : ""}</b>
      <span class="fl-sub">${H(m.address)}${m.port !== 22 ? ":" + m.port : ""} · <i class="dot ${m.up ? "ok" : m.lastError ? "err" : "idle"}"></i>${m.up ? "reachable" : m.lastError ? "unreachable" : "not checked"}</span>
      ${m.specs ? `<div class="fl-meters">${meter("cpu", cpu)}${meter("ram", pct(u.memUsed, u.memTotal))}${meter("disk", u.disk ? pct(u.disk.used, u.disk.total) : null)}</div>` : ""}
      <div class="fl-apps">${(m.apps || []).map(chip).join("") || '<span class="fl-chip muted">nothing known yet</span>'}</div>
    </div>
  </article>`;
}
const chip = (a) => `<span class="fl-chip" title="${H(a.name)}${a.version ? " " + H(a.version) : ""}">${LOGO[a.id] ? `<img src="${LOGO[a.id]}" alt="">` : ""}${H(a.name)}</span>`;
const meter = (label, v) => `<span class="fl-meter ${v != null && v > 85 ? "hot" : ""}" title="${label} ${v == null ? "unknown" : v + "%"}"><i style="width:${v || 0}%"></i><em>${label}</em></span>`;

function applyPan(el) {
  const world = el.querySelector(".fl-world");
  if (!world) return;
  world.style.transform = `translate(${FS.pan.x}px, ${FS.pan.y}px) scale(${FS.pan.k})`;
  const z = el.querySelector(".fl-zoom");
  if (z) z.textContent = Math.round(FS.pan.k * 100) + "%";
}

function wireCanvas(el, by) {
  const canvas = el.querySelector(".fl-canvas");
  let drag = null;
  canvas.addEventListener("pointerdown", (e) => {
    const node = e.target.closest(".fl-node:not(.hub)");
    const t = e.target.closest("[data-fl]");
    if (t) return;
    drag = { x: e.clientX, y: e.clientY, node: node || null, moved: false,
             from: node ? { ...(by[node.dataset.id] || { x: 0, y: 0 }) } : { ...FS.pan } };
    canvas.setPointerCapture(e.pointerId);
  });
  canvas.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    if (drag.node) {
      const x = drag.from.x + dx / FS.pan.k, y = drag.from.y + dy / FS.pan.k;
      FS.moved.set(drag.node.dataset.id, { x, y });
      drag.node.style.left = x + "px"; drag.node.style.top = y + "px";
    } else {
      FS.pan.x = drag.from.x + dx; FS.pan.y = drag.from.y + dy;
      FS.fitKey = "held";
      applyPan(el);
    }
  });
  const stop = (e) => {
    if (drag?.node && drag.moved) drawGraph(el);
    drag = null;
    try { canvas.releasePointerCapture(e.pointerId); } catch { /* already gone */ }
  };
  canvas.addEventListener("pointerup", stop);
  canvas.addEventListener("pointercancel", stop);
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const k = Math.max(0.4, Math.min(2, FS.pan.k * (e.deltaY < 0 ? 1.1 : 0.9)));
    FS.pan.k = k; FS.fitKey = "held"; applyPan(el);
  }, { passive: false });
  canvas.addEventListener("click", (e) => {
    const t = e.target.closest("[data-fl]");
    if (!t) return;
    if (t.dataset.fl === "in") { FS.pan.k = Math.min(2, FS.pan.k * 1.2); FS.fitKey = "held"; }
    else if (t.dataset.fl === "out") { FS.pan.k = Math.max(0.4, FS.pan.k / 1.2); FS.fitKey = "held"; }
    else { FS.moved.clear(); FS.fitKey = null; drawGraph(el); return; }
    applyPan(el);
  });
}

// ------------------------------------------------------------------ the panel
function panel() {
  const m = selected();
  if (!m) {
    return `<aside class="fl-panel card lit">
      <h2>Pick a machine</h2>
      <p class="muted">Pick one to see its specs, how loaded it is and what runs on it — and to install an app on it,
         open it in Termix, swap an app with another machine, or make it the standby for this one.</p>
      ${machines().length > 1 ? `<button class="btn sm" data-act="fl-swap">${I.swap} Swap an app between two machines</button>` : ""}
      <div class="fl-key">
        <span><i class="dot ok"></i>reachable</span><span><i class="dot err"></i>unreachable</span><span class="fl-tag">standby</span>
      </div>
    </aside>`;
  }
  const u = m.usage || {}, s = m.specs || {};
  const cpu = u.load != null && u.cores ? Math.min(100, Math.round((u.load / u.cores) * 100)) : null;
  return `<aside class="fl-panel card lit">
    <div class="fl-head">
      <div><h2>${H(m.name)}</h2>
        <p class="mono small">${H(m.user)}@${H(m.address)}${m.port !== 22 ? ":" + m.port : ""}</p></div>
      <button class="iconbtn" data-act="fl-close" aria-label="Close">${I.close}</button>
    </div>
    ${m.lastError ? `<div class="fl-warn"><b>Cannot reach it.</b> ${H(m.lastError)}</div>` : ""}
    <div class="fl-facts">
      <div><span>status</span><b><i class="dot ${m.up ? "ok" : "err"}"></i>${m.up ? "reachable" : "not answering"}</b></div>
      <div><span>last seen</span><b>${ago(m.lastSeen)}</b></div>
      <div><span>system</span><b>${H(m.os || "–")}</b></div>
      <div><span>machine</span><b>${H(s.model || m.arch || "–")}</b></div>
      <div><span>cores</span><b>${s.cores ?? "–"}</b></div>
      <div><span>memory</span><b>${fmtB(s.mem)}</b></div>
      <div><span>disk</span><b>${s.disk ? `${fmtB(s.disk.total)}` : "–"}</b></div>
      <div><span>up for</span><b>${dur(u.uptime)}</b></div>
    </div>
    <div class="fl-bars">
      ${bar("Processor", cpu, u.load != null ? `load ${u.load} on ${u.cores || "?"} cores` : "not checked")}
      ${bar("Memory", pct(u.memUsed, u.memTotal), `${fmtB(u.memUsed)} of ${fmtB(u.memTotal)}`)}
      ${bar("Disk", u.disk ? pct(u.disk.used, u.disk.total) : null, u.disk ? `${fmtB(u.disk.used)} of ${fmtB(u.disk.total)}` : "not checked")}
      ${u.tempC ? bar("Temperature", Math.min(100, Math.round((u.tempC / 85) * 100)), `${u.tempC} °C`) : ""}
    </div>
    <h3>What runs on it</h3>
    ${(m.apps || []).length ? `<ul class="fl-applist">${m.apps.map((a) => `<li>
        ${LOGO[a.id] ? `<img src="${LOGO[a.id]}" alt="">` : I.box}
        <b>${H(a.name)}</b><span class="mono small">${H(a.version || "")}</span>
        ${a.url ? `<a class="btn sm ghost" href="${H(a.url)}" target="_blank" rel="noopener">${I.ext} Open</a>` : ""}
      </li>`).join("")}</ul>`
      : `<p class="muted">Nothing Aegis knows by name${m.probedAt ? "" : " — it has not been looked at yet"}.</p>`}
    <div class="fl-acts">
      <button class="btn sm" data-act="fl-probe">${I.refresh} Look again</button>
      <button class="btn sm" data-act="fl-install">${I.box} Install an app</button>
      ${FS.data.termix ? `<button class="btn sm" data-act="fl-termix">${I.term} Open in Termix</button>` : ""}
      ${machines().length > 1 ? `<button class="btn sm" data-act="fl-swap">${I.swap} Swap an app</button>` : ""}
      <button class="btn sm ${m.standby ? "" : "ghost"}" data-act="fl-standby">${I.shield} ${m.standby ? "Standby is on" : "Make it the standby"}</button>
      <button class="btn sm danger ghost" data-act="fl-forget">${I.trash} Forget</button>
    </div>
    ${m.standby ? `<p class="fl-note">${I.shield} This machine keeps a copy of this gate${m.standbyState?.at ? `, last refreshed ${ago(m.standbyState.at)}` : ""}.
       If this host stops answering at <span class="mono">${H(m.standbyState?.url || "")}</span> it starts that copy, says what went wrong, and
       tries to start this one again. <button class="link" data-act="fl-standby-refresh">Refresh the copy now</button></p>` : ""}
    ${m.probe?.docker?.length ? `<details class="fl-more"><summary>${m.probe.docker.length} containers</summary>
      <ul class="fl-raw">${m.probe.docker.map((c) => `<li><b>${H(c.name)}</b> <span class="mono small">${H(c.image)}</span> <span class="muted">${H(c.status)}</span></li>`).join("")}</ul></details>` : ""}
    ${m.probe?.units?.length ? `<details class="fl-more"><summary>${m.probe.units.length} services running</summary>
      <ul class="fl-raw">${m.probe.units.map((u2) => `<li class="mono small">${H(u2)}</li>`).join("")}</ul></details>` : ""}
    <p class="fl-foot muted">Linked ${ago(m.addedAt)} · looked at ${ago(m.probedAt)}${(m.candidates || []).length > 1 ? ` · also answers on ${H(m.candidates.filter((c) => c !== m.address).slice(0, 3).join(", "))}` : ""}</p>
  </aside>`;
}
const bar = (label, v, sub) => `<div class="fl-bar${v != null && v > 85 ? " hot" : ""}">
  <span>${label}</span><i><b style="width:${v || 0}%"></b></i><em>${v == null ? "–" : v + "%"}</em><small>${H(sub)}</small></div>`;

// ------------------------------------------------------------------ doing things
export async function click(el, act) {
  const m = selected();
  if (act === "fl-copy") {
    try { await navigator.clipboard.writeText(el.dataset.text); X.toast("Copied"); } catch { X.toast("Copy it by hand"); }
    return true;
  }
  if (act === "fl-pick") { FS.sel = el.dataset.id === FS.sel ? null : el.dataset.id; X.render(); return true; }
  if (act === "fl-close") { FS.sel = null; X.render(); return true; }
  if (act === "fl-link") { linkForm(); return true; }
  if (act === "fl-manual") { manualForm(); return true; }
  if (act === "fl-swap") { swapForm(); return true; }
  if (!m) return false;
  if (act === "fl-probe") {
    el.disabled = true;
    try { await X.api(`/__gate/api/fleet/${m.id}/probe`, { method: "POST", body: "{}" }); X.toast("Looked again"); }
    catch (e) { X.toast(e.message); }
    await load(); X.render();
    return true;
  }
  if (act === "fl-install") { installForm(m); return true; }
  if (act === "fl-termix") { termixForm(m); return true; }
  if (act === "fl-standby") { m.standby ? standbyOffForm(m) : standbyForm(m); return true; }
  if (act === "fl-standby-refresh") { await job(`/__gate/api/fleet/${m.id}/standby/refresh`, {}); return true; }
  if (act === "fl-forget") { forgetForm(m); return true; }
  return false;
}

// Start a job and follow it in a modal, the way an addon job is followed.
async function job(path, body) {
  let j;
  try { j = (await X.api(path, { method: "POST", body: JSON.stringify(body || {}) })).job; }
  catch (e) { X.toast(e.message); return; }
  X.closeModal();
  X.jobRun(j, `/__gate/api/fleet/jobs/${j.id}`, async () => { await load(); X.render(); });
}

function linkForm() {
  X.openModal(`<h2>Link a machine</h2>
    <p>Run this on the other machine. It adds one key to that user's <span class="mono">authorized_keys</span>
       and tells this dashboard where to find it. Nothing else is sent, and it is asked for no password.</p>
    <div id="flInv"><p class="fl-wait"><span class="spin"></span> making the command…</p></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Close</button></div>`, async (mo) => {
    let inv;
    try { inv = await X.api("/__gate/api/fleet/invite", { method: "POST", body: JSON.stringify({ base: location.origin }) }); }
    catch (e) { mo.querySelector("#flInv").innerHTML = `<p class="err-msg">${H(e.message)}</p>`; return; }
    FS.link = inv;
    mo.querySelector("#flInv").innerHTML = `
      <div class="fl-cmd"><code>${H(inv.command)}</code>
        <button class="btn sm" data-act="fl-copy" data-text="${H(inv.command)}">${I.copy} Copy</button></div>
      <p class="muted small">Good for 30 minutes, once. <a class="link" href="${H(inv.base)}/__gate/fleet/join?t=${H(inv.token)}" target="_blank" rel="noopener">See exactly what it runs</a>.</p>
      <details class="fl-more"><summary>No curl on that machine?</summary>
        <p class="small">Add this line to its <span class="mono">~/.ssh/authorized_keys</span>, then use <b>Add by hand</b> here.</p>
        <div class="fl-cmd"><code>${H(inv.manual)}</code><button class="btn sm" data-act="fl-copy" data-text="${H(inv.manual)}">${I.copy} Copy</button></div></details>
      <p class="fl-wait" id="flWait"><span class="spin"></span> waiting for that machine…</p>`;
    pollForLink(mo, machines().length);
  });
}

// While the link modal is open, watch for the machine turning up.
function pollForLink(mo, was) {
  clearInterval(FS.pollTimer);
  FS.pollTimer = setInterval(async () => {
    if (!document.body.contains(mo)) { clearInterval(FS.pollTimer); return; }
    try { await load(); } catch { return; }
    if (machines().length > was) {
      clearInterval(FS.pollTimer);
      const fresh = machines()[machines().length - 1];
      FS.sel = fresh.id;
      const w = mo.querySelector("#flWait");
      if (w) w.innerHTML = `<b class="ok-msg">${H(fresh.name)} is linked.</b> Looking at what it runs…`;
      setTimeout(() => { X.closeModal(); X.render(); }, 1400);
    }
  }, 2500);
}

function manualForm() {
  X.openModal(`<h2>Add a machine by hand</h2>
    <p>For a machine whose <span class="mono">authorized_keys</span> already has this gate's key. Give any address
       that reaches it: a domain, a LAN or subnet address, a public address, a Tailscale name, a bare hostname.</p>
    <label class="fld"><span>Address</span><input id="flAddr" placeholder="192.168.1.50, forge.example.com, forge-claude"></label>
    <div class="row2">
      <label class="fld"><span>User</span><input id="flUser" placeholder="alex"></label>
      <label class="fld"><span>SSH port</span><input id="flPort" type="number" value="22" min="1" max="65535"></label>
    </div>
    <label class="fld"><span>Name it (optional)</span><input id="flName" placeholder="the address, if you leave this empty"></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">Add it</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", async () => {
      const b = mo.querySelector("#flGo"); b.disabled = true; b.textContent = "Checking…";
      try {
        const r = await X.api("/__gate/api/fleet/add", { method: "POST", body: JSON.stringify({
          address: mo.querySelector("#flAddr").value.trim(), user: mo.querySelector("#flUser").value.trim(),
          port: Number(mo.querySelector("#flPort").value) || 22, name: mo.querySelector("#flName").value.trim() }) });
        FS.sel = r.id; X.closeModal(); X.toast("Linked"); await load(); X.render();
      } catch (e) { mo.querySelector("#flErr").textContent = e.message; b.disabled = false; b.textContent = "Add it"; }
    });
  });
}

function installForm(m) {
  const rows = catalog().map((c) => {
    const has = (m.apps || []).some((a) => a.id === c.id);
    return `<label class="fl-pick${has ? " has" : ""}">
      <input type="radio" name="flApp" value="${H(c.id)}" ${c.installable && !has ? "" : "disabled"}>
      <span>${LOGO[c.id] ? `<img src="${LOGO[c.id]}" alt="">` : ""}<b>${H(c.name)}</b>
      <small>${has ? "already on this machine" : H(c.note)}</small></span></label>`;
  }).join("");
  X.openModal(`<h2>Install on ${H(m.name)}</h2>
    <p>Aegis runs that project's own installer (or the addon's setup) over the link, and shows you its output as it goes.</p>
    ${rows}
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">Install it</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", () => {
      const pick = mo.querySelector('input[name="flApp"]:checked');
      if (!pick) { mo.querySelector("#flErr").textContent = "Pick one first."; return; }
      job(`/__gate/api/fleet/${m.id}/install`, { app: pick.value });
    });
  });
}

function swapForm() {
  const swappable = catalog().filter((c) => c.swappable);
  const opts = (sel) => machines().map((m) => `<option value="${H(m.id)}" ${m.id === sel ? "selected" : ""}>${H(m.name)}</option>`).join("");
  X.openModal(`<h2>Swap an app between two machines</h2>
    <p>Each machine's copy of the app and all of its data change places. Both are stopped first and started again
       after; neither machine's old data is deleted — it is kept beside the new one.</p>
    <label class="fld"><span>App</span><select id="flApp">${swappable.map((c) => `<option value="${H(c.id)}">${H(c.name)}</option>`).join("")}</select></label>
    <div class="row2">
      <label class="fld"><span>This machine</span><select id="flA">${opts(FS.sel || machines()[0]?.id)}</select></label>
      <label class="fld"><span>swaps with</span><select id="flB">${opts(machines().find((m) => m.id !== (FS.sel || machines()[0]?.id))?.id)}</select></label>
    </div>
    <label class="row fl-confirm"><input type="checkbox" id="flOk"><span>I understand both apps stop while their data changes places.</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">Swap them</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", () => {
      const a = mo.querySelector("#flA").value, b = mo.querySelector("#flB").value;
      if (a === b) { mo.querySelector("#flErr").textContent = "Pick two different machines."; return; }
      if (!mo.querySelector("#flOk").checked) { mo.querySelector("#flErr").textContent = "Tick the box first."; return; }
      job("/__gate/api/fleet/swap", { app: mo.querySelector("#flApp").value, a, b, confirm: true });
    });
  });
}

function termixForm(m) {
  X.openModal(`<h2>Open ${H(m.name)} in Termix</h2>
    <p>This adds the machine to Termix as a host — its address <span class="mono">${H(m.address)}</span>, its SSH
       port <span class="mono">${m.port}</span> and the user <span class="mono">${H(m.user)}</span> — so you can open
       a terminal on it there. Termix asks for its own login, which Aegis uses once and does not keep.</p>
    <div class="row2">
      <label class="fld"><span>Termix user</span><input id="flTu" autocomplete="off"></label>
      <label class="fld"><span>Termix password</span><input id="flTp" type="password" autocomplete="off"></label>
    </div>
    <label class="fld"><span>How Termix signs in to the machine</span><select id="flAuth">
      <option value="key">With this gate's own key (nothing new to type)</option>
      <option value="password">With that machine's password</option></select></label>
    <label class="fld" id="flPwWrap" hidden><span>That machine's password</span><input id="flHp" type="password" autocomplete="off"></label>
    <label class="row fl-confirm"><input type="checkbox" id="flOk"><span>Add it to Termix.</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">Add and open</button></div>`, (mo) => {
    mo.querySelector("#flAuth").addEventListener("change", (e) => {
      mo.querySelector("#flPwWrap").hidden = e.target.value !== "password";
    });
    mo.querySelector("#flGo").addEventListener("click", async () => {
      const b = mo.querySelector("#flGo");
      if (!mo.querySelector("#flOk").checked) { mo.querySelector("#flErr").textContent = "Tick the box first."; return; }
      b.disabled = true; b.textContent = "Adding…";
      try {
        const r = await X.api(`/__gate/api/fleet/${m.id}/termix`, { method: "POST", body: JSON.stringify({
          username: mo.querySelector("#flTu").value, password: mo.querySelector("#flTp").value,
          auth: mo.querySelector("#flAuth").value, hostPassword: mo.querySelector("#flHp").value, confirm: true }) });
        X.closeModal();
        X.toast(r.existed ? `${m.name} was already in Termix` : `${m.name} added to Termix`);
        window.open("/__gate/open/termix", "_blank", "noopener");
        await load(); X.render();
      } catch (e) { mo.querySelector("#flErr").textContent = e.message; b.disabled = false; b.textContent = "Add and open"; }
    });
  });
}

function standbyForm(m) {
  X.openModal(`<h2>Make ${H(m.name)} the standby</h2>
    <p>A copy of this gate is put on that machine and kept current: its code, this login, the domain and the tunnels.
       It does not run. A small watcher there checks this host every half minute; if it misses four checks in a row it
       starts the copy, says what went wrong, and — only while this host is answering at all — runs a restart script on it.</p>
    <p class="muted small">This gate's own machine key is <b>not</b> copied: a standby cannot reach your other machines.
       The watcher gets its own key, which is allowed in here only to run that restart script.</p>
    <label class="fld"><span>Where this gate answers</span><input id="flUrl" value="${H(location.origin)}"></label>
    <div class="row2">
      <label class="fld"><span>Check every (seconds)</span><input id="flInt" type="number" value="30" min="10" max="3600"></label>
      <label class="fld"><span>Take over after (misses)</span><input id="flMiss" type="number" value="4" min="2" max="60"></label>
    </div>
    <label class="row fl-confirm"><input type="checkbox" id="flOk"><span>Copy this gate — login included — to ${H(m.name)}.</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">Set it up</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", () => {
      if (!mo.querySelector("#flOk").checked) { mo.querySelector("#flErr").textContent = "Tick the box first."; return; }
      job(`/__gate/api/fleet/${m.id}/standby`, { on: true, confirm: true, url: mo.querySelector("#flUrl").value.trim(),
        interval: Number(mo.querySelector("#flInt").value) || 30, misses: Number(mo.querySelector("#flMiss").value) || 4 });
    });
  });
}
function standbyOffForm(m) {
  X.openModal(`<h2>Stop using ${H(m.name)} as the standby?</h2>
    <p>The watcher is stopped and removed, the copy of this gate is deleted from that machine, and its key stops
       working here. The machine itself stays linked.</p>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Keep it</button>
      <button class="btn danger" id="flGo">Stop the standby</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", () => job(`/__gate/api/fleet/${m.id}/standby`, { on: false }));
  });
}

function forgetForm(m) {
  X.openModal(`<h2>Forget ${H(m.name)}?</h2>
    <p>Aegis takes its key back off that machine and drops it from here. Nothing installed on it is touched, and
       the machine keeps running whatever it runs.</p>
    <label class="row fl-confirm"><input type="checkbox" id="flKeep"><span>Leave the key in its <span class="mono">authorized_keys</span> (if the machine is off, say, and you will link it again)</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn danger" id="flGo">Forget it</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", async () => {
      const b = mo.querySelector("#flGo"); b.disabled = true; b.textContent = "Forgetting…";
      try {
        const keep = mo.querySelector("#flKeep").checked;
        const r = await X.api(`/__gate/api/fleet/${m.id}${keep ? "?keep-key=1" : ""}`, { method: "DELETE" });
        X.closeModal(); FS.sel = null;
        X.toast(r.removed ? "Forgotten, and the key is off it" : r.why ? `Forgotten (its key could not be removed: ${r.why})` : "Forgotten");
        await load(); X.render();
      } catch (e) { mo.querySelector("#flErr").textContent = e.message; b.disabled = false; b.textContent = "Forget it"; }
    });
  });
}

// ------------------------------------------------------------------ the chooser
// An app that lives on more than one machine asks which one you mean.
// `here` is this machine's own copy, if it has one.
export function places(me, appId, here) {
  const fleetOnes = ((me?.fleet?.apps || {})[appId] || []).filter((p) => p.url);
  const list = [];
  if (here) list.push({ name: "This machine", sub: location.host, url: here, self: true });
  for (const p of fleetOnes) list.push({ name: p.name, sub: `${p.address}${p.version ? ` · v${p.version}` : ""}`, url: p.url, up: p.up });
  return list;
}

// Stands on its own (the home page has no modal of its own to lend us).
export function chooser(title, list, open) {
  const scrim = document.createElement("div");
  scrim.className = "scrim";
  scrim.innerHTML = `<div class="card lit modal" role="dialog" aria-modal="true">
    <h2>${H(title)}</h2>
    <p>It is on more than one of your machines. Which one?</p>
    <div class="fl-choose">${list.map((p, i) => `<button class="fl-choice" data-i="${i}">
      <span class="fl-ico">${p.self ? I.hub : I.machine}</span>
      <span><b>${H(p.name)}</b><small>${H(p.sub)}</small></span>
      ${p.up === false ? '<i class="dot err" title="not answering"></i>' : '<i class="dot ok"></i>'}
    </button>`).join("")}</div>
    <div class="modal-actions"><button class="btn ghost" data-fl-close="1">Cancel</button></div></div>`;
  const shut = () => { scrim.remove(); document.removeEventListener("keydown", esc); };
  const esc = (e) => { if (e.key === "Escape") shut(); };
  scrim.addEventListener("mousedown", (e) => { if (e.target === scrim) shut(); });
  scrim.addEventListener("click", (e) => {
    if (e.target.closest("[data-fl-close]")) return shut();
    const b = e.target.closest(".fl-choice");
    if (!b) return;
    shut();
    open(list[Number(b.dataset.i)]);
  });
  document.addEventListener("keydown", esc);
  document.body.append(scrim);
}

// The one call a page makes: if the app is on more than one machine, ask;
// otherwise do what the link would have done. Returns true when it asked.
export function askWhere(me, appId, label, here, open) {
  const list = places(me, appId, here);
  if (list.length < 2) return false;
  chooser(`Open ${label}`, list, (p) => open(p));
  return true;
}
