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
  tidy: SVG('<rect x="3" y="4" width="7" height="6" rx="1.5"/><rect x="14" y="4" width="7" height="6" rx="1.5"/><rect x="14" y="14" width="7" height="6" rx="1.5"/><path d="M10 7h4M17.5 10v4"/>'),
  full: SVG('<path d="M15 3h6v6M21 3l-7 7M9 21H3v-6M3 21l7-7"/>'),
  move: SVG('<path d="M4 12h13M13 6l6 6-6 6"/><path d="M4 6v12"/>'),
};
const LOGOS = { "aegis-burrow": "/__gate/logos/aegis-burrow.svg", "selkies-forge": "/__gate/logos/forge.svg",
               bulwark: "/__gate/logos/bulwark.svg", termix: "/__gate/logos/termix.svg" };
// an addon's program ("<addon>:<program>") wears its addon's logo
const LOGO = new Proxy(LOGOS, { get: (o, id) => o[id] || (typeof id === "string" && /^[a-z0-9-]+:[a-z0-9-]+$/.test(id) ? `/__gate/api/addons/${id.split(":")[0]}/image` : undefined) });

// The tab's own state. `data` is the last /__gate/api/fleet.
// sel: {id, kind: "machine" | "app" | "hub"}; detail: id -> {at, d} (the full /fleet/<id>)
export const FS = { data: null, sel: null, at: 0, link: null, pollTimer: null, fitKey: null, G: null,
                    pan: { x: 0, y: 0, k: 1 }, moved: new Map(), detail: new Map() };

let X = null;        // the bits tunnels.js lends us: api, toast, openModal, closeModal, render, jobRun
export function init(host) { X = host; }

export const machines = () => FS.data?.machines || [];
const selected = () => (FS.sel?.kind === "machine" && machines().find((m) => m.id === FS.sel.id)) || null;
const catalog = () => FS.data?.catalog || [];
const appName = (id) => catalog().find((c) => c.id === id)?.name || id;

export async function load(fresh) {
  const d = await X.api("/__gate/api/fleet");
  FS.data = d; FS.at = Date.now();
  if (FS.sel?.kind === "machine" && !machines().some((m) => m.id === FS.sel.id)) FS.sel = null;
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
// Drawn the way a workflow editor draws one (Bulwark's Patterns page, n8n):
// cards on a dotted canvas, read left to right, joined by connections.
//
//   This gate  ->  your machines  ->  what runs on them
//
// A machine's line is green while it answers, red when it doesn't, gold for
// the standby. Hover a card or a line to trace it; click one and the panel
// beside the canvas tells everything about it. Drag the canvas to move, drag
// a card to place it, scroll (or pinch) to zoom; Fit, Tidy up, Full screen.
const NW = 240, HUB_H = 88, M_H = 92, A_H = 58, ROW = 14, COL_GAP = 92;
const STAGES = [["This gate", "the hub"], ["Your machines", "linked over SSH"], ["What runs on them", "apps and programs"]];

function model() {
  const d = FS.data, list = machines();
  const nodes = [{ id: "self", col: 0, type: "hub", h: HUB_H }];
  const apps = new Map();
  const addApp = (a, where) => {
    const k = `app:${a.id}`;
    const n = apps.get(k) || { id: k, col: 2, type: "app", h: A_H, appId: a.id, name: a.name, on: [] };
    n.on.push({ where, version: a.version || null, url: a.url || null });
    apps.set(k, n);
  };
  for (const a of d.here || []) addApp(a, "self");
  for (const m of list) { nodes.push({ id: m.id, col: 1, type: "machine", h: M_H, m }); for (const a of m.apps || []) addApp(a, m.id); }
  nodes.push(...[...apps.values()].sort((a, b) => b.on.length - a.on.length || a.name.localeCompare(b.name)));
  const edges = [];
  for (const m of list) edges.push({ a: "self", b: m.id, kind: m.standby ? "standby" : m.up ? "up" : m.lastError ? "down" : "idle" });
  for (const n of apps.values()) for (const o of n.on) edges.push({ a: o.where, b: n.id, kind: "app", app: n.appId });
  for (const e of edges) e.key = `${e.a}|${e.b}`;
  return { nodes, edges, byId: new Map(nodes.map((n) => [n.id, n])) };
}

function layout(G, cw) {
  // wide canvases spread the stages apart; narrow ones pull them in so the cards stay readable
  const gap = Math.round(Math.max(COL_GAP, Math.min(320, (cw / 0.95 - 3 * NW - 80) / 2)));
  const cols = [[], [], []];
  for (const n of G.nodes) cols[n.col].push(n);
  const hgt = cols.map((c) => c.reduce((s, n) => s + n.h + ROW, -ROW));
  const H = Math.max(...hgt, HUB_H);
  cols.forEach((c, i) => {
    let y = (H - hgt[i]) / 2;
    for (const n of c) {
      const mv = FS.moved.get(n.id);
      n.x = mv ? mv.x : i * (NW + gap); n.y = mv ? mv.y : y;
      y += n.h + ROW;
    }
  });
  G.gap = gap; G.height = H;
}

const EDGE_C = { up: "var(--ok)", down: "var(--err)", idle: "var(--faint)", standby: "#f2c14e", app: "var(--blue)" };
function edgePath(G, e) {
  const a = G.byId.get(e.a), b = G.byId.get(e.b);
  const x1 = a.x + NW, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
  const dx = Math.max(60, Math.abs(x2 - x1) * 0.5);
  e.mid = { x: (x1 + x2) / 2, y: (y1 + y2) / 2 };
  return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
}
function edgesSvg(G) {
  return G.edges.map((e) => {
    const d = edgePath(G, e);
    return `<g class="fw-edge ${e.kind}" data-key="${H(e.key)}" style="--c:${EDGE_C[e.kind]}"><path class="fw-line" d="${d}"/><path class="fw-flow" d="${d}"/><path class="fw-hit" d="${d}"/></g>`;
  }).join("");
}

const cpuOf = (m) => { const u = m.usage || {}; return u.load != null && u.cores ? Math.min(100, Math.round((u.load / u.cores) * 100)) : null; };
const stateOf = (m) => m.up ? (m.misses ? ["warn", "slow to answer"] : ["ok", "reachable"]) : m.lastError ? ["err", "not answering"] : ["idle", "not checked yet"];
function nodeHtml(n) {
  const c = n.type === "machine" ? EDGE_C[n.m.standby ? "standby" : n.m.up ? "up" : n.m.lastError ? "down" : "idle"] : n.type === "app" ? "var(--blue)" : "var(--ok)";
  const at = `data-id="${H(n.id)}" tabindex="0" role="button" style="left:${n.x}px;top:${n.y}px;height:${n.h}px;--c:${c}"`;
  if (n.type === "hub") {
    const d = FS.data;
    return `<div class="fw-node hub" ${at} aria-label="This machine">
      <i class="fw-port out"></i><span class="fw-ic">${I.hub}</span>
      <span class="fw-body"><b class="fw-title">${H(d.hub.name)}</b><span class="fw-sub">this machine · ${H(d.hub.hostname)}</span>
        <span class="fw-stats"><span><b>${machines().length}</b> linked</span><span><b>${machines().filter((m) => m.up).length}</b> up</span>${d.hub.version ? `<span>v${H(d.hub.version)}</span>` : ""}</span></span>
    </div>`;
  }
  if (n.type === "machine") {
    const m = n.m, u = m.usage || {}, [dot, said] = stateOf(m);
    return `<div class="fw-node machine ${m.up ? "up" : "down"}${m.standby ? " standby" : ""}" ${at} aria-label="${H(m.name)}: ${said}">
      <i class="fw-port in"></i><i class="fw-port out"></i><span class="fw-ic">${I.machine}</span>
      <span class="fw-body"><b class="fw-title">${H(m.name)}${m.standby ? '<em class="fw-tag gold">standby</em>' : ""}</b>
        <span class="fw-sub"><i class="dot ${dot}"></i>${said} · ${H(m.address)}</span>
        ${m.specs ? `<span class="fw-meters">${meter("cpu", cpuOf(m))}${meter("ram", pct(u.memUsed, u.memTotal))}${meter("disk", u.disk ? pct(u.disk.used, u.disk.total) : null)}</span>`
          : '<span class="fw-sub faint">not looked at yet</span>'}</span>
    </div>`;
  }
  const many = n.on.length > 1;
  return `<div class="fw-node app" ${at} aria-label="${H(n.name)} on ${n.on.length}">
    <i class="fw-port in"></i><span class="fw-ic">${LOGO[n.appId] ? `<img src="${LOGO[n.appId]}" alt="">` : I.box}</span>
    <span class="fw-body"><b class="fw-title">${H(n.name)}</b>
      <span class="fw-stats"><span><b>${n.on.length}</b> ${n.on.length === 1 ? "machine" : "machines"}</span>${many ? '<span class="fw-tag">on several</span>' : ""}${n.on.some((o) => o.url) ? `<span>${I.ext}</span>` : ""}</span></span>
  </div>`;
}
const meter = (label, v) => `<span class="fl-meter ${v != null && v > 85 ? "hot" : ""}" title="${label} ${v == null ? "unknown" : v + "%"}"><i style="width:${v || 0}%"></i><em>${label}</em></span>`;
const chip = (a) => `<span class="fl-chip" title="${H(a.name)}${a.version ? " " + H(a.version) : ""}">${LOGO[a.id] ? `<img src="${LOGO[a.id]}" alt="">` : ""}${H(a.name)}</span>`;

// The narrow-screen list: the same machines as plain cards.
function listCard(m) {
  const [dot, said] = stateOf(m), u = m.usage || {};
  return `<article class="fl-node${FS.sel?.id === m.id ? " on" : ""}${m.up ? "" : " down"}" data-act="fl-pick" data-kind="machine" data-id="${H(m.id)}" tabindex="0" role="link">
    <div class="fl-ico">${I.machine}</div>
    <div class="fl-body"><b>${H(m.name)}${m.standby ? `<span class="fl-tag">standby</span>` : ""}</b>
      <span class="fl-sub">${H(m.address)} · <i class="dot ${dot}"></i>${said}</span>
      ${m.specs ? `<div class="fl-meters">${meter("cpu", cpuOf(m))}${meter("ram", pct(u.memUsed, u.memTotal))}${meter("disk", u.disk ? pct(u.disk.used, u.disk.total) : null)}</div>` : ""}
      <div class="fl-apps">${(m.apps || []).map(chip).join("") || '<span class="fl-chip muted">nothing known yet</span>'}</div></div>
  </article>`;
}

function drawGraph(el, cards) {
  if (!el) return;
  const G = model();
  FS.G = G;
  if (cards) cards.innerHTML = machines().map(listCard).join("") || '<p class="muted small">Only this machine so far.</p>';
  el.innerHTML = `
    <div class="fw-canvas" tabindex="0" aria-label="Your machines. Drag to move, scroll to zoom.">
      <div class="fw-world"><svg class="fw-edges" width="10" height="10" aria-hidden="true"></svg><div class="fw-labels"></div><div class="fw-nodes"></div></div>
      <div class="fw-controls" role="toolbar" aria-label="Canvas">
        <button type="button" data-fl="in" title="Zoom in" aria-label="Zoom in">${I.zin}</button>
        <button type="button" data-fl="out" title="Zoom out" aria-label="Zoom out">${I.zout}</button>
        <button type="button" data-fl="fit" title="Fit to view" aria-label="Fit to view">${I.fit}</button>
        <button type="button" data-fl="tidy" title="Tidy up" aria-label="Tidy up">${I.tidy}</button>
        <button type="button" data-fl="full" title="Full screen (F)" aria-label="Full screen">${I.full}</button>
        <span class="fw-zoom">100%</span>
      </div>
      <div class="fw-legend"><span><i style="--c:var(--ok)"></i>answers</span><span><i style="--c:var(--err)"></i>not answering</span><span><i style="--c:#f2c14e"></i>standby</span><span><i style="--c:var(--blue)"></i>runs</span></div>
      ${machines().length ? '<div class="fw-hint">drag to move · scroll to zoom · <kbd>F</kbd> full screen · click a card</div>'
        : `<div class="fw-none"><p>Only this machine so far.</p><button class="btn sm primary" data-act="fl-link">${I.plus} Link one</button></div>`}
      <div class="fw-tip" hidden></div>
    </div>`;
  const canvas = el.querySelector(".fw-canvas");
  layout(G, canvas.clientWidth || 900);
  paint(el, G);
  wireCanvas(el, G);
  const key = `${G.nodes.length}:${G.edges.length}:${Math.round((canvas.clientWidth || 0) / 50)}`;
  if (FS.fitKey !== key) { FS.fitKey = key; fit(el, G); }
  applyPan(el);
}
function paint(el, G) {
  el.querySelector(".fw-nodes").innerHTML = G.nodes.map(nodeHtml).join("");
  el.querySelector(".fw-labels").innerHTML = STAGES.map(([t, s], i) => `<div class="fw-stage" style="left:${i * (NW + G.gap)}px;top:-58px;width:${NW}px"><b>${i + 1}</b><span>${t}<em>${s}</em></span></div>`).join("");
  el.querySelector(".fw-edges").innerHTML = edgesSvg(G);
  lightUp(el, G);
}
function moveEdges(el, G, id) {
  for (const e of G.edges) if (e.a === id || e.b === id) {
    const d = edgePath(G, e);
    el.querySelectorAll(`.fw-edge[data-key="${CSS.escape(e.key)}"] path`).forEach((p) => p.setAttribute("d", d));
  }
}
// a card and its lines (and the cards at their ends) stay lit; the rest steps back
function lightUp(el, G, hover = null) {
  const t = hover || (FS.sel ? { node: FS.sel.id } : null);
  const nodes = new Set(), edges = new Set();
  if (t?.node) {
    nodes.add(t.node);
    for (const e of G.edges) if (e.a === t.node || e.b === t.node) { edges.add(e.key); nodes.add(e.a); nodes.add(e.b); }
  } else if (t?.edge) { const e = G.edges.find((x) => x.key === t.edge); if (e) { edges.add(e.key); nodes.add(e.a); nodes.add(e.b); } }
  const canvas = el.querySelector(".fw-canvas");
  canvas.classList.toggle("dim", !!t);
  for (const n of el.querySelectorAll(".fw-node")) { n.classList.toggle("lit", nodes.has(n.dataset.id)); n.classList.toggle("sel", FS.sel?.id === n.dataset.id); }
  for (const g of el.querySelectorAll(".fw-edge")) g.classList.toggle("lit", edges.has(g.dataset.key));
}

function fit(el, G) {
  const canvas = el.querySelector(".fw-canvas");
  const cw = canvas.clientWidth || 900, ch = canvas.clientHeight || 520;
  const x0 = Math.min(...G.nodes.map((n) => n.x)), x1 = Math.max(...G.nodes.map((n) => n.x)) + NW;
  const y0 = Math.min(...G.nodes.map((n) => n.y)) - 64, y1 = Math.max(...G.nodes.map((n) => n.y + n.h));
  const k = Math.max(0.35, Math.min(1.1, (cw - 60) / (x1 - x0), (ch - 80) / (y1 - y0)));
  FS.pan = { k, x: (cw - (x1 - x0) * k) / 2 - x0 * k, y: (ch - 30 - (y1 - y0) * k) / 2 - y0 * k };
}
function applyPan(el) {
  const world = el.querySelector(".fw-world");
  if (!world) return;
  world.style.transform = `translate(${FS.pan.x}px, ${FS.pan.y}px) scale(${FS.pan.k})`;
  const z = el.querySelector(".fw-zoom");
  if (z) z.textContent = Math.round(FS.pan.k * 100) + "%";
}

function tipFor(G, t) {
  if (t.edge) {
    const e = G.edges.find((x) => x.key === t.edge), a = G.byId.get(e.a), b = G.byId.get(e.b);
    const nm = (n) => n.type === "hub" ? FS.data.hub.name : n.type === "machine" ? n.m.name : n.name;
    return e.kind === "app" ? `<b>${H(nm(b))}</b><span>runs on ${H(nm(a))}</span>`
      : `<b>${H(nm(b))}</b><span>${{ up: "answers over SSH", down: "not answering", idle: "not checked yet", standby: "keeps a copy of this gate" }[e.kind]}</span>`;
  }
  const n = G.byId.get(t.node);
  if (n.type === "machine") { const m = n.m; return `<b>${H(m.name)}</b><span>${H(m.os || "")}</span><em>last seen ${ago(m.lastSeen)}</em>`; }
  if (n.type === "app") return `<b>${H(n.name)}</b><span>on ${n.on.map((o) => o.where === "self" ? "this machine" : (G.byId.get(o.where)?.m.name || "?")).map(H).join(", ")}</span>`;
  return `<b>${H(FS.data.hub.name)}</b><span>this machine, the hub</span>`;
}

function wireCanvas(el, G) {
  const canvas = el.querySelector(".fw-canvas"), tip = el.querySelector(".fw-tip");
  let drag = null;
  const pick = (target) => {
    const n = G.byId.get(target);
    if (!n) return;
    FS.sel = FS.sel?.id === n.id ? null : { id: n.id, kind: n.type };
    lightUp(el, G);
    paintPanel();
    if (FS.sel?.kind === "machine") loadDetail(FS.sel.id);
    if (FS.sel?.kind === "hub" || FS.sel?.kind === "app") loadSelf();
  };
  canvas.addEventListener("pointerdown", (e) => {
    if (e.target.closest("[data-fl], .fw-controls, .fw-none")) return;
    const node = e.target.closest(".fw-node");
    drag = { x: e.clientX, y: e.clientY, node, moved: false, from: node ? { x: G.byId.get(node.dataset.id).x, y: G.byId.get(node.dataset.id).y } : { ...FS.pan } };
    canvas.setPointerCapture(e.pointerId);
    canvas.classList.add("panning");
  });
  canvas.addEventListener("pointermove", (e) => {
    if (!drag) {
      const hit = e.target.closest(".fw-node") ? { node: e.target.closest(".fw-node").dataset.id } : e.target.closest(".fw-edge") ? { edge: e.target.closest(".fw-edge").dataset.key } : null;
      lightUp(el, G, hit);
      if (hit) {
        const r = canvas.getBoundingClientRect();
        tip.innerHTML = tipFor(G, hit); tip.hidden = false;
        tip.style.left = Math.min(r.width - 260, e.clientX - r.left + 14) + "px"; tip.style.top = (e.clientY - r.top + 14) + "px";
      } else tip.hidden = true;
      return;
    }
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    if (!drag.moved) return;
    tip.hidden = true;
    if (drag.node) {
      const n = G.byId.get(drag.node.dataset.id);
      n.x = drag.from.x + dx / FS.pan.k; n.y = drag.from.y + dy / FS.pan.k;
      FS.moved.set(n.id, { x: n.x, y: n.y });
      drag.node.style.left = n.x + "px"; drag.node.style.top = n.y + "px";
      drag.node.classList.add("dragging");
      moveEdges(el, G, n.id);
    } else {
      FS.pan.x = drag.from.x + dx; FS.pan.y = drag.from.y + dy;
      FS.fitKey = "held";
      applyPan(el);
    }
  });
  const stop = (e) => {
    if (!drag) return;
    const d = drag; drag = null;
    canvas.classList.remove("panning");
    d.node?.classList.remove("dragging");
    try { canvas.releasePointerCapture(e.pointerId); } catch { /* gone */ }
    if (!d.moved) {
      if (d.node) pick(d.node.dataset.id);
      else { const ed = e.target.closest?.(".fw-edge"); if (ed) pick(ed.dataset.key.split("|")[1]); else if (FS.sel) { FS.sel = null; lightUp(el, G); paintPanel(); } }
    }
  };
  canvas.addEventListener("pointerup", stop);
  canvas.addEventListener("pointercancel", stop);
  canvas.addEventListener("pointerleave", () => { if (!drag) { tip.hidden = true; lightUp(el, G); } });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top;
    const k = Math.max(0.35, Math.min(2.2, FS.pan.k * Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0015))));
    FS.pan.x = px - ((px - FS.pan.x) * k) / FS.pan.k; FS.pan.y = py - ((py - FS.pan.y) * k) / FS.pan.k; FS.pan.k = k;
    FS.fitKey = "held"; applyPan(el);
  }, { passive: false });
  canvas.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.closest(".fw-node")) pick(e.target.closest(".fw-node").dataset.id);
    if (e.key === "f" || e.key === "F") toggleFull(el);
    if (e.key === "Escape" && FS.sel) { FS.sel = null; lightUp(el, G); paintPanel(); }
  });
  canvas.querySelector(".fw-controls").addEventListener("click", (e) => {
    const t = e.target.closest("[data-fl]");
    if (!t) return;
    const zoom = (f) => { const cw = canvas.clientWidth / 2, ch = canvas.clientHeight / 2, k = Math.max(0.35, Math.min(2.2, FS.pan.k * f));
      FS.pan.x = cw - ((cw - FS.pan.x) * k) / FS.pan.k; FS.pan.y = ch - ((ch - FS.pan.y) * k) / FS.pan.k; FS.pan.k = k; FS.fitKey = "held"; };
    if (t.dataset.fl === "in") zoom(1.2);
    else if (t.dataset.fl === "out") zoom(1 / 1.2);
    else if (t.dataset.fl === "fit") fit(el, G);
    else if (t.dataset.fl === "tidy") { FS.moved.clear(); layout(G, canvas.clientWidth); paint(el, G); fit(el, G); }
    else if (t.dataset.fl === "full") { toggleFull(el); return; }
    applyPan(el);
  });
}
function toggleFull(el) {
  const wrap = el.closest(".fl-wrap") || el;
  const on = !wrap.classList.contains("full");
  wrap.classList.toggle("full", on);
  document.documentElement.classList.toggle("fl-noscroll", on);
  FS.fitKey = null;
  drawGraph(el);
}

// ------------------------------------------------------------------ the panel
// Machines' full detail (the probe: containers, services, every disk, every
// address) is only in /fleet/<id>; it is fetched when one is picked.
async function loadDetail(id, fresh) {
  const have = FS.detail.get(id);
  if (!fresh && have && Date.now() - have.at < 20000) return;
  try { FS.detail.set(id, { at: Date.now(), d: await X.api(`/__gate/api/fleet/${id}`) }); }
  catch { return; }
  if (FS.sel?.id === id) paintPanel();
}
function paintPanel() {
  const p = document.getElementById("flPanel");
  if (p) p.innerHTML = panelHtml();
}
function panel() { return `<aside class="fl-panel card lit" id="flPanel" aria-live="polite">${panelHtml()}</aside>`; }

function panelHtml() {
  const s = FS.sel;
  if (s?.kind === "machine" && selected()) return machinePanel(selected());
  if (s?.kind === "app" && FS.G?.byId.get(s.id)) return appPanel(FS.G.byId.get(s.id));
  if (s?.kind === "hub") return hubPanel();
  return `<div class="fp-head" style="--c:var(--ok)"><span class="fp-kind">machines</span><h2>Pick a card</h2></div>
    <p class="muted">Click a machine to see everything about it: its hardware, how loaded it is, every disk and address, its
       containers and services, and what you can do to it from here. Click an app to see where it runs and move it.</p>
    <div class="fp-acts">
      <button class="btn sm primary" data-act="fl-link">${I.plus} Link a machine</button>
      ${machines().length > 1 ? `<button class="btn sm" data-act="fl-transfer">${I.move} Move an app</button><button class="btn sm" data-act="fl-swap">${I.swap} Swap an app</button>` : ""}
    </div>
    <div class="fl-key"><span><i class="dot ok"></i>answers</span><span><i class="dot warn"></i>slow to answer</span><span><i class="dot err"></i>not answering</span><span class="fl-tag">standby</span></div>`;
}

// This machine: the same panel as a linked one, from /fleet/self (the probe, run here).
async function loadSelf(fresh) {
  if (!fresh && FS.self && Date.now() - FS.self.at < 20000) return;
  if (FS.selfLoading) return;
  FS.selfLoading = true;
  try { FS.self = { at: Date.now(), d: await X.api(`/__gate/api/fleet/self${fresh ? "?fresh=1" : ""}`) }; }
  catch { /* the panel says it couldn't look */ }
  finally { FS.selfLoading = false; }
  if (FS.sel?.kind === "hub" || FS.sel?.kind === "app") paintPanel();
}
const manageOf = (where, app) => where === "self" ? FS.self?.d?.manage?.[app.id || app.appId] || null : app.url || null;

function hubPanel() {
  const d = FS.data, me = FS.self?.d, sb = machines().filter((m) => m.standby);
  const head = `<div class="fp-head" style="--c:var(--ok)"><span class="fp-kind">this machine · the hub</span><h2>${H(d.hub.name)}</h2>
      <p class="mono small">${H(me?.hostname || d.hub.hostname)}${d.hub.version ? ` · Aegis × Burrow ${H(d.hub.version)}` : ""}</p>
      <span class="pill ok"><i class="dot ok"></i>this machine${me ? ` · looked at ${ago(me.probedAt)}` : ""}</span>
      <button class="fp-x" data-act="fl-close" aria-label="Close">${I.close}</button></div>
    <div class="fp-acts main">
      ${FS.data.termix ? `<a class="btn sm primary" href="/__gate/open/termix" target="_blank" rel="noopener">${I.term} Open Termix</a>` : ""}
      <button class="btn sm" data-act="fl-self-again">${I.refresh} Look again</button>
      <a class="btn sm ghost" href="/__gate/settings">${I.shield} Settings</a>
    </div>`;
  if (!me) return `${head}<p class="fl-wait small"><span class="spin"></span> looking at this machine…</p>`;
  return `${head}${machineBody(me, me.probe, { hub: true })}
    <h3>Standby</h3>
    <p class="small ${sb.length ? "" : "muted"}">${sb.length ? `${sb.map((m) => H(m.name)).join(", ")} keeps a copy of this gate and takes over if it stops answering.` : "No machine keeps a copy of this gate. Pick one and choose “Make it the standby”."}</p>
    <div class="fp-acts"><button class="btn sm primary" data-act="fl-link">${I.plus} Link a machine</button><button class="btn sm" data-act="fl-manual">Add by hand</button>
      ${machines().length ? `<button class="btn sm" data-act="fl-move-gate">${I.move} Move this gate to another machine</button>` : ""}</div>`;
}

const usageLine = (u) => u ? `<span class="fl-use">${u.cpu != null ? `<b>${Number(u.cpu).toFixed(u.cpu < 10 ? 1 : 0)}%</b> cpu` : ""}${u.mem != null ? ` <b>${fmtB(u.mem)}</b> memory` : ""}</span>` : "";

function appPanel(n) {
  const where = n.on.map((o) => ({ ...o, m: o.where === "self" ? null : machines().find((x) => x.id === o.where) }));
  const c = catalog().find((x) => x.id === n.appId);
  const others = machines().filter((m) => !n.on.some((o) => o.where === m.id));
  const usageAt = (o) => o.where === "self" ? (FS.self?.d?.apps || []).find((a) => a.id === n.appId)?.usage : (o.m?.apps || []).find((a) => a.id === n.appId)?.usage;
  const hostOf = (o) => o.where === "self" ? FS.self?.d : o.m;
  return `<div class="fp-head" style="--c:var(--blue)"><span class="fp-kind">app</span>
      <h2>${LOGO[n.appId] ? `<img class="fp-logo" src="${LOGO[n.appId]}" alt="">` : ""}${H(n.name)}</h2>
      <p class="small muted">on ${n.on.length} ${n.on.length === 1 ? "machine" : "machines"}${c?.note ? ` · ${H(c.note)}` : ""}</p>
      <button class="fp-x" data-act="fl-close" aria-label="Close">${I.close}</button></div>
    <h3>Where it runs, and what it uses there</h3>
    <div class="fl-where">${where.map((o) => {
      const h = hostOf(o), u = h?.usage || {}, au = usageAt(o), link = manageOf(o.where, { id: n.appId, url: o.url });
      return `<div class="fl-place">
        <div class="fl-place-h"><span class="fl-ico sm">${o.m ? I.machine : I.hub}</span>
          <span class="grow"><b>${o.m ? H(o.m.name) : "This machine"}</b>${o.version ? ` <span class="mono small">${H(o.version)}</span>` : ""}
            <small class="faint">${o.m ? `${H(o.m.address)} · ${stateOf(o.m)[1]}` : H(h?.hostname || "the hub")}</small></span>
          ${link ? `<a class="btn sm primary" href="${H(link)}" target="_blank" rel="noopener">${I.ext} Manage</a>` : ""}</div>
        ${au ? `<div class="fl-appuse">${I.box} ${H(n.name)} uses ${usageLine(au)}</div>` : '<div class="fl-appuse muted small">its own use isn’t known (no service or container Aegis can read)</div>'}
        ${h?.specs ? `<div class="fw-meters wide">${meter("cpu", cpuOf(h))}${meter("ram", pct(u.memUsed, u.memTotal))}${meter("disk", u.disk ? pct(u.disk.used, u.disk.total) : null)}</div>
          <small class="faint">that machine: ${fmtB(u.memUsed)} of ${fmtB(u.memTotal)} memory · load ${u.load ?? "–"} on ${u.cores || "?"} cores</small>` : o.where === "self" && !FS.self ? '<small class="faint"><span class="spin"></span> looking…</small>' : ""}
        ${o.m && c?.swappable && machines().length > 1 ? `<div class="fp-acts"><button class="btn sm" data-act="fl-transfer" data-app="${H(n.appId)}" data-from="${H(o.m.id)}">${I.move} Move or copy it</button>
          <button class="btn sm ghost" data-act="fl-pick" data-kind="machine" data-id="${H(o.m.id)}">${I.machine} The machine</button></div>` : ""}
      </div>`; }).join("")}</div>
    ${c?.swappable || n.appId === "aegis-burrow" ? "" : `<p class="small muted">${H(c?.note || "Aegis can't move this one between machines.")}</p>`}
    <div class="fp-acts">
      ${n.appId === "aegis-burrow" && n.on.some((o) => o.where === "self") && machines().length ? `<button class="btn sm" data-act="fl-move-gate">${I.move} Move this gate to another machine</button>` : ""}
      ${c?.installable && others.length ? `<button class="btn sm" data-act="fl-install-app" data-app="${H(n.appId)}">${I.box} Install it on another machine</button>` : ""}
      ${c?.swappable && n.on.filter((o) => o.where !== "self").length > 1 ? `<button class="btn sm" data-act="fl-swap" data-app="${H(n.appId)}">${I.swap} Swap two copies</button>` : ""}
    </div>`;
}

function machinePanel(m) {
  const det = FS.detail.get(m.id)?.d || {}, p = det.probe || null;
  const [dot, said] = stateOf(m);
  const tx = det.termix || m.termix || null, hasTermix = !!FS.data.termix;
  return `<div class="fp-head" style="--c:${EDGE_C[m.standby ? "standby" : m.up ? "up" : m.lastError ? "down" : "idle"]}">
      <span class="fp-kind">machine${m.standby ? " · standby" : ""}${m.via === "agent" ? " · through its agent" : ""}</span>
      <h2>${H(m.name)}</h2>
      <p class="mono small">${H(m.user)}@${H(m.address)}${m.port !== 22 ? ":" + m.port : ""}</p>
      <span class="pill ${dot === "idle" ? "" : dot}"><i class="dot ${dot}"></i>${said}${m.lastSeen ? ` · ${ago(m.lastSeen)}` : ""}</span>
      <button class="fp-x" data-act="fl-close" aria-label="Close">${I.close}</button></div>
    ${m.lastError && !m.up ? `<div class="fl-warn"><b>Cannot reach it.</b> ${H(m.lastError)}</div>` : ""}
    <div class="fp-acts main">
      ${hasTermix && tx?.hostId != null ? `<button class="btn sm primary" data-act="fl-terminal">${I.term} Terminal</button>` : ""}
      ${hasTermix ? `<button class="btn sm${tx ? " ghost" : " primary"}" data-act="fl-termix">${I.term} ${tx ? "In Termix ✓" : "Add to Termix"}</button>` : ""}
      <button class="btn sm" data-act="fl-probe">${I.refresh} Look again</button>
    </div>
    ${p ? machineBody(m, p, {}) : `<p class="fl-wait small"><span class="spin"></span> loading everything it knows about it…</p>`}
    <h3>Keep it safe</h3>
    <div class="fp-acts">
      <button class="btn sm ${m.standby ? "" : "ghost"}" data-act="fl-standby">${I.shield} ${m.standby ? "Standby is on" : "Make it the standby"}</button>
      <button class="btn sm danger ghost" data-act="fl-forget">${I.trash} Forget</button>
    </div>
    ${m.standby ? `<p class="fl-note">${I.shield} This machine keeps a copy of this gate${m.standbyState?.at ? `, last refreshed ${ago(m.standbyState.at)}` : ""}.
       If this host stops answering at <span class="mono">${H(m.standbyState?.url || "")}</span> and is not just slow, it starts that copy and tries to start this one again.
       <button class="link" data-act="fl-standby-refresh">Refresh the copy now</button></p>` : ""}
    <p class="fl-foot muted">Linked ${ago(m.addedAt)} · looked at ${ago(m.probedAt)}</p>`;
}

// What a machine is, how loaded it is, what runs on it and everything else the
// probe saw - for a linked machine and for this one alike.
function machineBody(m, p, { hub }) {
  const u = m.usage || {}, s = m.specs || {}, cpu = cpuOf(m);
  const fact = (k, v) => `<div><span>${k}</span><b title="${H(v ?? "–")}">${H(v ?? "–")}</b></div>`;
  return `<div class="fl-bars">
      ${bar("Processor", cpu, u.load != null ? `load ${(p?.cpu?.load || [u.load]).map((x) => Number(x).toFixed(2)).join(" · ")} on ${u.cores || "?"} cores` : "not checked")}
      ${bar("Memory", pct(u.memUsed, u.memTotal), `${fmtB(u.memUsed)} of ${fmtB(u.memTotal)}`)}
      ${bar("Disk", u.disk ? pct(u.disk.used, u.disk.total) : null, u.disk ? `${fmtB(u.disk.used)} of ${fmtB(u.disk.total)} on ${H(u.disk.mount || "/")}` : "not checked")}
      ${u.tempC ? bar("Temperature", Math.min(100, Math.round((u.tempC / 85) * 100)), `${u.tempC} °C`) : ""}
    </div>
    <h3>The machine</h3>
    <div class="fl-facts">
      ${fact("system", m.os || p?.os?.pretty)}${fact("kernel", p?.os?.kernel)}
      ${fact("hardware", s.model || m.arch)}${fact("processor", p?.cpu?.model)}
      ${fact("cores", s.cores)}${fact("memory", s.mem ? fmtB(s.mem) : null)}
      ${fact("architecture", m.arch || p?.os?.arch)}${fact("virtual", p?.os?.virt || "no")}
      ${fact("hostname", m.hostname || p?.host?.hostname)}${fact("up for", dur(u.uptime))}
      ${fact("ssh port", p?.ssh?.port || m.port)}${fact(hub ? "runs as" : "signs in as", p?.host?.user || m.user)}
    </div>
    <h3>What runs on it</h3>
    ${(m.apps || []).length ? `<ul class="fl-applist">${m.apps.map((a) => {
      const c = catalog().find((x) => x.id === a.id), link = hub ? manageOf("self", a) : a.url;
      return `<li>${LOGO[a.id] ? `<img src="${LOGO[a.id]}" alt="">` : I.box}
        <span class="grow"><b>${H(a.name)}</b> <span class="mono small">${H(a.version || "")}</span>${a.usage ? `<small class="faint">${usageLine(a.usage)}</small>` : ""}</span>
        ${link ? `<a class="btn sm ghost" href="${H(link)}" target="_blank" rel="noopener">${I.ext} ${hub ? "Manage" : "Open"}</a>` : ""}
        ${!hub && c?.swappable && machines().length > 1 ? `<button class="btn sm ghost" data-act="fl-transfer" data-app="${H(a.id)}" data-from="${H(m.id)}" title="Move or copy it to another machine">${I.move}</button>` : ""}
      </li>`; }).join("")}</ul>`
      : `<p class="muted small">Nothing Aegis knows by name${m.probedAt ? "" : " — it has not been looked at yet"}.</p>`}
    ${hub ? "" : `<div class="fp-acts">
      <button class="btn sm" data-act="fl-install">${I.box} Install an app</button>
      ${machines().length > 1 ? `<button class="btn sm" data-act="fl-transfer" data-from="${H(m.id)}">${I.move} Move an app</button><button class="btn sm" data-act="fl-swap">${I.swap} Swap</button>` : ""}
    </div>`}
    ${p.disks?.length ? `<h3>Disks</h3><div class="fl-bars">${p.disks.map((dk) => bar(H(dk.mount), pct(dk.used, dk.total), `${fmtB(dk.used)} used · ${fmtB(dk.free)} free of ${fmtB(dk.total)}`)).join("")}</div>` : ""}
    <h3>Network</h3>
    <ul class="fp-addr">${[...new Set([hub ? null : m.address, ...(m.candidates || []), ...(p.addresses || [])])].filter(Boolean).map((a) => `<li><span class="mono">${H(a)}</span>${a === m.address ? '<span class="fl-tag">used</span>' : ""}
      <button class="iconbtn sm" data-act="fl-copy" data-text="${H(a)}" aria-label="Copy">${I.copy}</button></li>`).join("")}</ul>
    ${p.ssh?.listening?.length ? `<p class="small muted">Listening on ${p.ssh.listening.slice(0, 24).map((x) => `<span class="mono">${x}</span>`).join(", ")}${p.ssh.listening.length > 24 ? " …" : ""}</p>` : ""}
    ${p.docker ? `<details class="fl-more" ${p.docker.length && p.docker.length < 8 ? "open" : ""}><summary>${p.docker.length} ${p.docker.length === 1 ? "container" : "containers"} running</summary>
      <ul class="fl-raw">${p.docker.map((c) => { const cu = p.usage?.containers?.[c.name]; return `<li><b>${H(c.name)}</b> <span class="mono small">${H(c.image)}</span><br><span class="muted small">${H(c.status)}${c.ports ? ` · ${H(c.ports)}` : ""}</span>${cu ? `<br>${usageLine(cu)}` : ""}</li>`; }).join("") || '<li class="muted">none</li>'}</ul></details>`
      : '<p class="small muted">No Docker there (or this user may not use it).</p>'}
    ${p.units?.length ? `<details class="fl-more"><summary>${p.units.length} services running</summary>
      <ul class="fl-raw">${p.units.map((x) => `<li class="mono small">${H(x)}</li>`).join("")}</ul></details>` : ""}`;
}
const bar = (label, v, sub) => `<div class="fl-bar${v != null && v > 85 ? " hot" : ""}">
  <span>${label}</span><i><b style="width:${v || 0}%"></b></i><em>${v == null ? "–" : v + "%"}</em><small>${sub}</small></div>`;

// ------------------------------------------------------------------ doing things
export async function click(el, act) {
  const m = selected();
  if (act === "fl-copy") {
    try { await navigator.clipboard.writeText(el.dataset.text); X.toast("Copied"); } catch { X.toast("Copy it by hand"); }
    return true;
  }
  if (act === "fl-pick") {
    FS.sel = FS.sel?.id === el.dataset.id ? null : { id: el.dataset.id, kind: el.dataset.kind || "machine" };
    X.render();
    if (FS.sel?.kind === "machine") loadDetail(FS.sel.id);
    // a narrow screen shows the panel below the list: take the reader to it
    if (FS.sel && window.innerWidth <= 980) document.getElementById("flPanel")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return true;
  }
  if (act === "fl-close") { FS.sel = null; X.render(); return true; }
  if (act === "fl-self-again") { el.disabled = true; await loadSelf(true); return true; }
  if (act === "fl-link") { linkForm(); return true; }
  if (act === "fl-manual") { manualForm(); return true; }
  if (act === "fl-swap") { swapForm(el.dataset.app); return true; }
  if (act === "fl-transfer") { transferForm(el.dataset.app, el.dataset.from || m?.id); return true; }
  if (act === "fl-install-app") { installAppForm(el.dataset.app); return true; }
  if (act === "fl-move-gate") { moveGateForm(); return true; }
  if (!m) return false;
  if (act === "fl-probe") {
    el.disabled = true;
    try { await X.api(`/__gate/api/fleet/${m.id}/probe`, { method: "POST", body: "{}" }); X.toast("Looked again"); }
    catch (e) { X.toast(e.message); }
    await load(); FS.detail.delete(m.id); X.render(); loadDetail(m.id, true);
    return true;
  }
  if (act === "fl-install") { installForm(m); return true; }
  if (act === "fl-termix") { termixForm(m); return true; }
  if (act === "fl-terminal") { openTerminal(m); return true; }
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
      FS.sel = { id: fresh.id, kind: "machine" };
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
        FS.sel = { id: r.id, kind: "machine" }; X.closeModal(); X.toast("Linked"); await load(); X.render();
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

function swapForm(pre) {
  const swappable = catalog().filter((c) => c.swappable);
  const opts = (sel) => machines().map((m) => `<option value="${H(m.id)}" ${m.id === sel ? "selected" : ""}>${H(m.name)}</option>`).join("");
  X.openModal(`<h2>Swap an app between two machines</h2>
    <p>Each machine's copy of the app and all of its data change places. Both are stopped first and started again
       after; neither machine's old data is deleted — it is kept beside the new one.</p>
    <label class="fld"><span>App</span><select id="flApp">${swappable.map((c) => `<option value="${H(c.id)}" ${c.id === pre ? "selected" : ""}>${H(c.name)}</option>`).join("")}</select></label>
    <div class="row2">
      <label class="fld"><span>This machine</span><select id="flA">${opts(selected()?.id || machines()[0]?.id)}</select></label>
      <label class="fld"><span>swaps with</span><select id="flB">${opts(machines().find((m) => m.id !== (selected()?.id || machines()[0]?.id))?.id)}</select></label>
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
    <label class="row fl-confirm"><input type="checkbox" id="flOk"><span>Add it to Termix${m.termix ? " (it is there already: this only refreshes what Aegis knows)" : ""}.</span></label>
    <label class="row fl-confirm"><input type="checkbox" id="flOpen" checked><span>Then open a terminal on it in a new tab.</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">Add to Termix</button></div>`, (mo) => {
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
        if (mo.querySelector("#flOpen")?.checked) openTerminal({ ...m, termix: { hostId: r.id } });
        await load(); FS.detail.delete(m.id); X.render(); loadDetail(m.id, true);
      } catch (e) { mo.querySelector("#flErr").textContent = e.message; b.disabled = false; b.textContent = "Add to Termix"; }
    });
  });
}

// Termix opens straight into a terminal on that host (its ?view=terminal&hostId=).
// The new tab is opened before anything is awaited, so no popup blocker minds.
function openTerminal(m) {
  const id = m.termix?.hostId;
  const url = id != null ? `/__gate/open/termix?view=terminal&hostId=${encodeURIComponent(id)}` : "/__gate/open/termix";
  window.open(url, "_blank", "noopener");
}

// One app and its data, from one machine to another: a copy, or a move.
function transferForm(appId, fromId) {
  const movable = catalog().filter((c) => c.swappable);
  if (!movable.length) { X.toast("Nothing Aegis knows can be moved between machines yet."); return; }
  const has = (mid, app) => machines().find((x) => x.id === mid)?.apps?.some((a) => a.id === app);
  const app0 = appId && movable.some((c) => c.id === appId) ? appId : (movable.find((c) => has(fromId, c.id)) || movable[0]).id;
  const from0 = fromId && has(fromId, app0) ? fromId : (machines().find((x) => has(x.id, app0)) || machines()[0])?.id;
  const opts = (sel, skip) => machines().filter((x) => x.id !== skip).map((x) => `<option value="${H(x.id)}" ${x.id === sel ? "selected" : ""}>${H(x.name)}${x.up ? "" : " (not answering)"}</option>`).join("");
  X.openModal(`<h2>${I.move} Move an app to another machine</h2>
    <p>Its data goes with it. The app is stopped on the first machine while its data is read, so what arrives is complete.
       Whatever the second machine had is moved aside there, never deleted.</p>
    <label class="fld"><span>App</span><select id="flApp">${movable.map((c) => `<option value="${H(c.id)}" ${c.id === app0 ? "selected" : ""}>${H(c.name)}</option>`).join("")}</select></label>
    <div class="row2">
      <label class="fld"><span>From</span><select id="flFrom">${opts(from0)}</select></label>
      <label class="fld"><span>To</span><select id="flTo">${opts(machines().find((x) => x.id !== from0)?.id, null)}</select></label>
    </div>
    <div class="fl-modes" role="radiogroup">
      <label class="fl-mode"><input type="radio" name="flMode" value="copy" checked><span><b>Copy</b><small>Both machines run it afterwards; the first one starts again as soon as its data is read.</small></span></label>
      <label class="fl-mode"><input type="radio" name="flMode" value="move"><span><b>Move</b><small>Only the second runs it afterwards. The first keeps its data, stopped and no longer started at boot.</small></span></label>
    </div>
    <p class="small muted" id="flHint"></p>
    <label class="row fl-confirm"><input type="checkbox" id="flOk"><span>Stop it for as long as its data takes to copy.</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">${I.move} Start</button></div>`, (mo) => {
    const hint = () => {
      const app = mo.querySelector("#flApp").value, f = mo.querySelector("#flFrom").value, t = mo.querySelector("#flTo").value;
      const name = (id) => machines().find((x) => x.id === id)?.name || "?";
      mo.querySelector("#flHint").textContent = !has(f, app) ? `${name(f)} doesn't have ${appName(app)} as far as Aegis knows - look at it again first if it does.`
        : has(t, app) ? `${name(t)} already has it: its copy and data are moved aside and replaced.` : `${name(t)} doesn't have it yet: Aegis installs it there first.`;
    };
    for (const id of ["#flApp", "#flFrom", "#flTo"]) mo.querySelector(id).addEventListener("change", hint);
    hint();
    mo.querySelector("#flGo").addEventListener("click", () => {
      const from = mo.querySelector("#flFrom").value, to = mo.querySelector("#flTo").value;
      if (from === to) { mo.querySelector("#flErr").textContent = "Pick two different machines."; return; }
      if (!mo.querySelector("#flOk").checked) { mo.querySelector("#flErr").textContent = "Tick the box first."; return; }
      job("/__gate/api/fleet/transfer", { app: mo.querySelector("#flApp").value, from, to, mode: mo.querySelector('input[name="flMode"]:checked').value, confirm: true });
    });
  });
}

// The whole gate - login, domain, tunnels, addons, machines - onto a linked machine.
function moveGateForm() {
  const ok = machines().filter((x) => x.up);
  X.openModal(`<h2>${I.move} Move this gate to another machine</h2>
    <p>Everything this dashboard is goes with it: the login, the domain and its tunnel, every tunnel, the addons and their
       settings, the certificates, and these machines. The other machine gets Aegis × Burrow first if it doesn't have it.
       Once it answers there, this machine steps aside and only shows where the gate went.</p>
    <ul class="fl-steps">
      <li>Your address stays the same: after a minute, this same link opens the gate on the new machine.</li>
      <li>Addons start themselves there (their services are installed again where they need to be).</li>
      <li>Apps beside the gate on this machine (Termix, Selkies Forge) stay here: move them with <b>Move an app</b>.</li>
      <li>This machine becomes one of the new gate's machines, so you can move back from there.</li>
    </ul>
    ${ok.length ? `<label class="fld"><span>Move it to</span><select id="flTo">${ok.map((x) => `<option value="${H(x.id)}">${H(x.name)} · ${H(x.address)}</option>`).join("")}</select></label>`
      : '<p class="err-msg">No linked machine is answering right now.</p>'}
    <label class="row fl-confirm"><input type="checkbox" id="flOk"><span>Move the whole gate there. This machine stops being the gate.</span></label>
    <div class="err-msg" id="flErr"></div>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo" ${ok.length ? "" : "disabled"}>${I.move} Move it</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", () => {
      if (!mo.querySelector("#flOk").checked) { mo.querySelector("#flErr").textContent = "Tick the box first."; return; }
      job(`/__gate/api/fleet/${mo.querySelector("#flTo").value}/movegate`, { confirm: true });
    });
  });
}

// "Install it on another machine", from an app's card.
function installAppForm(appId) {
  const c = catalog().find((x) => x.id === appId);
  const free = machines().filter((x) => !(x.apps || []).some((a) => a.id === appId));
  if (!c || !free.length) { X.toast("Every machine has it already."); return; }
  X.openModal(`<h2>Install ${H(c.name)}</h2><p>${H(c.note || "")}</p>
    <label class="fld"><span>On</span><select id="flOn">${free.map((x) => `<option value="${H(x.id)}">${H(x.name)}${x.up ? "" : " (not answering)"}</option>`).join("")}</select></label>
    <div class="modal-actions"><button class="btn ghost" data-act="close">Cancel</button><button class="btn primary" id="flGo">${I.box} Install it</button></div>`, (mo) => {
    mo.querySelector("#flGo").addEventListener("click", () => job(`/__gate/api/fleet/${mo.querySelector("#flOn").value}/install`, { app: appId }));
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
