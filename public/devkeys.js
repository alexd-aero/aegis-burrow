// Settings → Developer: API keys for scripts and programs (aegis/apikeys.mjs), the
// API's switch, a playground that calls /__gate/v1 as you, ready-to-paste examples,
// and what every key did. A new key is shown once, here, and never again.
import { h, toast, ago } from "./common.js";

const DV = { tab: "keys", data: null, err: "", busy: false, made: null, edit: null, form: null,
             pg: { method: "GET", path: "/overview", body: "", out: null, busy: false }, ex: "curl", rerender: () => {} };
const EXPIRY = [["", "Never"], ["7d", "7 days"], ["30d", "30 days"], ["90d", "90 days"], ["365d", "1 year"]];
const PRESETS = [["full", "Everything"], ["read", "Read only"], ["custom", "Pick"]];
const QUICK = [["GET", "/overview"], ["GET", "/tunnels"], ["GET", "/addons"], ["GET", "/fleet"], ["GET", "/domains"], ["GET", "/audit"], ["GET", "/update"], ["GET", "/whoami"]];

async function call(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts, headers: { "X-Gate": "1", "Content-Type": "application/json", ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
async function loadDev() {
  try { DV.data = await call("/__gate/api/devkeys"); DV.err = ""; } catch (e) { DV.err = e.message; }
  DV.rerender();
}
const base = () => DV.data?.base || `${location.origin}/__gate/v1`;
const blankForm = () => ({ name: "", note: "", preset: "full", scopes: ["read"], appsMode: "all", apps: [], expires: "", ips: "", rate: "600" });
function formOf(k) {
  const preset = k.scopes.includes("full") ? "full" : k.scopes.length === 1 && k.scopes[0] === "read" ? "read" : "custom";
  return { id: k.id, name: k.name, note: k.note, preset, scopes: k.scopes.filter((s) => s !== "full"), appsMode: k.apps === "all" ? "all" : "some",
           apps: k.apps === "all" ? [] : [...k.apps], expires: k.expires ? "keep" : "", ips: (k.ips || []).join(", "), rate: String(k.rate) };
}
const scopesOf = (f) => (f.preset === "full" ? ["full"] : f.preset === "read" ? ["read"] : f.scopes);
const opensApps = (f) => scopesOf(f).some((s) => s === "full" || s === "apps");

// ------------------------------------------------------------------ the section
export function devBody() {
  const d = DV.data;
  if (!d) return DV.err ? `<p class="err-msg">${h(DV.err)}</p>` : '<p class="muted"><i class="spin"></i> Loading…</p>';
  const live = d.keys.filter((k) => k.status === "on").length;
  const head = `<div class="mod dv-head">
      <span class="mod-ico" aria-hidden="true"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="m8 9-4 3 4 3M16 9l4 3-4 3M13.5 6l-3 12"/></svg></span>
      <div class="grow"><b>API access</b> ${d.enabled ? `<span class="pill ok">on</span>` : '<span class="pill">off</span>'} <span class="faint small">${d.keys.length} ${d.keys.length === 1 ? "key" : "keys"}${d.keys.length ? `, ${live} working` : ""}</span>
        <p class="muted small">Scripts, bots and your own apps drive Aegis × Burrow with a key: tunnels, addons, machines, domains, updates, everything the dashboard does,
        and they can open the apps behind your login. Off: every key is refused, and kept.</p>
        <div class="dv-base"><span class="faint small">Base URL</span> <span class="mono">${h(base())}</span>
          <button type="button" class="btn sm ghost" data-dv="copy" data-v="${h(base())}">Copy</button></div></div>
      <label class="switch" title="${d.enabled ? "On" : "Off"}"><input type="checkbox" id="dvOn" ${d.enabled ? "checked" : ""} aria-label="API access on or off"><i></i></label>
    </div>`;
  const tabs = `<div class="seg dv-tabs" role="tablist">${[["keys", `Keys${d.keys.length ? ` (${d.keys.length})` : ""}`], ["new", "New key"], ["play", "Playground"], ["examples", "Examples"], ["log", "Activity"]]
    .map(([k, l]) => `<button type="button" role="tab" data-dv="tab" data-v="${k}" class="${DV.tab === k ? "on" : ""}" aria-selected="${DV.tab === k}">${l}</button>`).join("")}</div>`;
  const body = DV.made ? madeView() : DV.tab === "keys" ? (DV.edit ? keyForm(DV.edit, true) : keysView())
    : DV.tab === "new" ? keyForm(DV.form || (DV.form = blankForm()), false)
    : DV.tab === "play" ? playView() : DV.tab === "examples" ? examplesView() : logView();
  return `${head}${tabs}<div class="dv-body">${body}</div>`;
}

function scopeChips(scopes) {
  return scopes.map((s) => `<span class="pill dv-scope${s === "full" ? " full" : ""}" title="${h(DV.data.scopes[s]?.note || "")}">${h(DV.data.scopes[s]?.name || s)}</span>`).join("");
}
function appsText(k) {
  if (!(k.scopes.includes("full") || k.scopes.includes("apps"))) return "no apps";
  if (k.apps === "all") return "every app";
  const names = k.apps.map((id) => DV.data.apps.find((a) => a.id === id)?.name || id);
  return names.length ? names.join(", ") : "no apps picked";
}
function keysView() {
  const d = DV.data;
  if (!d.keys.length) return `<div class="dv-empty"><p class="muted">No keys yet. A key is how a script signs in: it goes in a header, never in a link.</p>
      <button type="button" class="btn primary" data-dv="tab" data-v="new">Make your first key</button></div>`;
  const status = (k) => k.status === "on" ? '<span class="pill ok"><i class="dot ok"></i>working</span>'
    : k.status === "expired" ? '<span class="pill warn">expired</span>' : '<span class="pill">switched off</span>';
  return `<div class="dv-keys">${d.keys.map((k) => `<div class="dv-key${k.status === "on" ? "" : " off"}">
      <div class="grow">
        <div class="row flexwrap" style="gap:8px"><b>${h(k.name)}</b> ${status(k)} <span class="mono faint small">${h(k.prefix)}</span></div>
        ${k.note ? `<p class="muted small" style="margin:4px 0 0">${h(k.note)}</p>` : ""}
        <div class="chips">${scopeChips(k.scopes)}</div>
        <p class="faint small dv-meta">Opens ${h(appsText(k))} · ${k.expires ? (k.status === "expired" ? "expired " : "expires ") + h(new Date(k.expires).toLocaleDateString()) : "never expires"}
          · ${k.rate ? `${k.rate} requests/min` : "no rate limit"}${k.ips.length ? ` · only from <span class="mono">${h(k.ips.join(", "))}</span>` : ""}
          <br>Made ${ago(k.created)}${k.createdBy ? ` by ${h(k.createdBy)}` : ""}${k.rolled ? ` · rolled ${ago(k.rolled)}` : ""} ·
          ${k.last ? `last used ${ago(k.last.at)} from <span class="mono">${h(k.last.ip)}</span> (<span class="mono">${h(k.last.method)} ${h(k.last.path)}</span>) · ${k.uses.toLocaleString()} ${k.uses === 1 ? "call" : "calls"}` : "never used"}</p>
      </div>
      <div class="dv-acts">
        <button type="button" class="btn sm" data-dv="edit" data-id="${k.id}">Edit</button>
        <button type="button" class="btn sm" data-dv="toggle" data-id="${k.id}">${k.disabled ? "Switch on" : "Switch off"}</button>
        <button type="button" class="btn sm" data-dv="roll" data-id="${k.id}" title="A new secret; the old key stops working at once">Roll</button>
        <button type="button" class="btn sm danger" data-dv="revoke" data-id="${k.id}">Revoke</button>
      </div></div>`).join("")}</div>
    <div class="row end"><button type="button" class="btn sm ghost danger" data-dv="revoke-all">Revoke every key</button></div>`;
}

function keyForm(f, editing) {
  const d = DV.data, sc = scopesOf(f);
  const scopeGrid = f.preset === "custom" ? `<div class="dv-scopes">${Object.entries(d.scopes).filter(([id]) => id !== "full").map(([id, x]) => `
      <label class="dv-sc${f.scopes.includes(id) ? " on" : ""}"><input type="checkbox" data-dvsc="${id}" ${f.scopes.includes(id) ? "checked" : ""}>
        <span><b>${h(x.name)}</b><span class="faint small">${h(x.note)}</span></span></label>`).join("")}</div>`
    : `<p class="faint small">${h(d.scopes[f.preset]?.note || "")}</p>`;
  const apps = opensApps(f) ? `<div class="field"><span>Apps it opens <span class="faint">(tunnels behind your login and apps under the dashboard, with the key in a header)</span></span>
      <div class="seg"><button type="button" data-dv="apps-mode" data-v="all" class="${f.appsMode === "all" ? "on" : ""}">Every app</button><button type="button" data-dv="apps-mode" data-v="some" class="${f.appsMode === "some" ? "on" : ""}">Only these</button></div>
      ${f.appsMode === "some" ? (d.apps.length ? `<div class="dv-apps">${d.apps.map((a) => `<label class="check"><input type="checkbox" data-dvapp="${h(a.id)}" ${f.apps.includes(a.id) ? "checked" : ""}>
          <span>${h(a.name)} <span class="faint small mono">${a.kind === "tunnel" ? h(a.id.slice(7)) + " · " + h(a.access) : "app"}</span></span></label>`).join("")}</div>`
        : '<p class="faint small">No tunnels or apps yet.</p>') : ""}</div>` : "";
  return `<form class="dv-form" id="dvForm" autocomplete="off">
    ${editing ? `<p class="small"><b>Editing ${h(f.name)}</b> <span class="faint">· the key itself stays the same</span></p>` : ""}
    <div class="row flexwrap"><label class="field grow"><span>Name</span><input class="input" id="dvName" maxlength="60" value="${h(f.name)}" placeholder="Home Assistant, deploy bot, my phone…" required></label>
      <label class="field grow"><span>Note <span class="faint">(optional)</span></span><input class="input" id="dvNote" maxlength="200" value="${h(f.note)}" placeholder="what uses it"></label></div>
    <div class="field"><span>What it may do</span>
      <div class="seg">${PRESETS.map(([v, l]) => `<button type="button" data-dv="preset" data-v="${v}" class="${f.preset === v ? "on" : ""}">${l}</button>`).join("")}</div>
      ${scopeGrid}</div>
    ${apps}
    <div class="row flexwrap">
      <div class="field"><span>Expires</span><div class="seg">${(editing && f.expires === "keep" ? [["keep", "Keep as is"], ...EXPIRY] : EXPIRY).map(([v, l]) => `<button type="button" data-dv="expires" data-v="${v}" class="${f.expires === v ? "on" : ""}">${l}</button>`).join("")}</div></div>
      <label class="field"><span>Rate limit <span class="faint">(requests a minute, apps' too; 0 = none)</span></span><input class="input mono" id="dvRate" inputmode="numeric" value="${h(f.rate)}" style="max-width:140px"></label></div>
    <label class="field"><span>Only from these addresses <span class="faint">(optional: IPs or ranges, like 203.0.113.7, 10.0.0.0/8)</span></span>
      <input class="input mono" id="dvIps" value="${h(f.ips)}" placeholder="anywhere" spellcheck="false" autocapitalize="none"></label>
    ${sc.includes("full") ? `<div class="note-box warn-box small"><b>Everything</b> means anyone holding this key can do what you can signed in: change tunnels, install addons that run code, update or roll back Aegis, reach your machines and open every app. Keep it in a secret store, give it an expiry or an address list if you can, and revoke it here the moment it leaks. No key can see or make keys, or change your login.</div>` : ""}
    <div class="err-msg" id="dvErr">${h(DV.formErr || "")}</div>
    <div class="row end">${editing ? '<button type="button" class="btn ghost" data-dv="edit-cancel">Cancel</button>' : ""}
      <button type="submit" class="btn primary" ${DV.busy ? "disabled" : ""}>${DV.busy ? '<i class="spin"></i> Saving…' : editing ? "Save" : "Make the key"}</button></div>
  </form>`;
}

function madeView() {
  const m = DV.made;
  return `<div class="dv-made">
    <p><b>${m.rolled ? "The new secret for" : "Your key:"} ${h(m.name)}</b>. Copy it now: <b>it is never shown again</b>. Aegis keeps only a hash of it.</p>
    <div class="row dv-secret"><input class="input mono" readonly value="${h(m.key)}" id="keySecret"><button type="button" class="btn primary" data-dv="copy" data-v="${h(m.key)}">Copy</button></div>
    <p class="faint small">Try it from any terminal:</p>
    <pre class="dv-code">${h(`curl -s ${base()}/whoami \\\n  -H "Authorization: Bearer ${m.key}"`)}</pre>
    <div class="row end"><button type="button" class="btn" data-dv="made-done">I've saved it</button></div></div>`;
}

function playView() {
  const p = DV.pg;
  const out = p.out ? `<div class="dv-out"><div class="row" style="gap:8px"><span class="pill ${p.out.status < 300 ? "ok" : p.out.status < 500 ? "warn" : "err"}">${p.out.status}</span>
      <span class="faint small mono">${h(p.out.method)} ${h(p.out.path)} · ${p.out.ms} ms · ${p.out.size.toLocaleString()} bytes</span><span class="grow"></span>
      <button type="button" class="btn sm ghost" data-dv="copy" data-v="${h(p.out.text)}">Copy</button></div>
      <pre class="dv-code dv-res">${h(p.out.text)}</pre></div>` : "";
  return `<p class="muted small">Calls the API as you, from this page: what a key with <b>Everything</b> would get. Changes are real.</p>
    <div class="chips" style="margin:0 0 10px">${QUICK.map(([m, pth]) => `<button type="button" class="chip" data-dv="quick" data-m="${m}" data-p="${h(pth)}"><span class="mono">${m} ${h(pth)}</span></button>`).join("")}</div>
    <form class="dv-play" id="dvPlay">
      <div class="row"><select class="input dv-method" id="dvMethod">${["GET", "POST", "PATCH", "PUT", "DELETE"].map((m) => `<option ${p.method === m ? "selected" : ""}>${m}</option>`).join("")}</select>
        <div class="dv-path grow"><span class="mono faint">/__gate/v1</span><input class="input mono" id="dvPath" value="${h(p.path)}" spellcheck="false" autocapitalize="none"></div>
        <button type="submit" class="btn primary" ${p.busy ? "disabled" : ""}>${p.busy ? '<i class="spin"></i>' : "Send"}</button></div>
      ${p.method === "GET" || p.method === "DELETE" ? "" : `<textarea class="input mono dv-body-in" id="dvBody" rows="5" spellcheck="false" placeholder='{"port": 8080, "name": "my app"}'>${h(p.body)}</textarea>`}
      <div class="row" style="justify-content:flex-end;gap:8px;margin-top:8px"><button type="button" class="btn sm ghost" data-dv="as-curl">Copy as curl</button></div>
    </form>${out}`;
}

const EX = {
  curl: (b) => `# who am I, and what may this key do
curl -s ${b}/whoami -H "Authorization: Bearer $AEGIS_KEY"

# every tunnel
curl -s ${b}/tunnels -H "Authorization: Bearer $AEGIS_KEY"

# publish port 8080 behind your login, as app.<your tunnel domain>
curl -s -X POST ${b}/tunnels -H "Authorization: Bearer $AEGIS_KEY" \\
  -H "Content-Type: application/json" -d '{"port": 8080, "name": "My app", "sub": "app", "access": "login"}'

# switch it to public, then remove it
curl -s -X PATCH ${b}/tunnels/8080 -H "Authorization: Bearer $AEGIS_KEY" -d '{"access": "public"}'
curl -s -X DELETE ${b}/tunnels/8080 -H "Authorization: Bearer $AEGIS_KEY"

# update an addon, then follow its job
curl -s -X POST ${b}/addons/bulwark/update -H "Authorization: Bearer $AEGIS_KEY" -d '{}'

# open an app behind the login with the same key (a key with the Apps scope)
curl -s https://app.example.com/ -H "Authorization: Bearer $AEGIS_KEY"`,
  node: (b) => `// Node 18+, no packages. examples/api/aegis-api.mjs in the repository has the full client.
const BASE = "${b}";
const KEY = process.env.AEGIS_KEY;

async function aegis(method, path, body) {
  const r = await fetch(BASE + path, {
    method,
    headers: { Authorization: \`Bearer \${KEY}\`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json();
  if (!r.ok) throw new Error(\`\${r.status}: \${j.error}\`);
  return j;
}

const { tunnels } = await aegis("GET", "/tunnels");
for (const t of tunnels) console.log(t.port, t.name, t.url, t.access);

// publish, wait a moment, print its address
const t = await aegis("POST", "/tunnels", { port: 8080, name: "My app", access: "login" });
console.log("live at", t.url);`,
  python: (b) => `# Python 3, standard library only. examples/api/aegis_api.py has the full client.
import json, os, urllib.request

BASE = "${b}"
KEY = os.environ["AEGIS_KEY"]

def aegis(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

print(aegis("GET", "/whoami"))
for t in aegis("GET", "/tunnels")["tunnels"]:
    print(t["port"], t.get("name"), t.get("url"), t.get("access"))

# addons with an update waiting, updated one by one
for u in aegis("GET", "/addons/updates")["updates"]:
    print("updating", u["id"]); aegis("POST", f"/addons/{u['id']}/update", {})`,
  cli: () => `# on this machine, the same thing without a browser
aegis keys create "deploy bot" --scopes read,tunnels --expires 90
aegis keys create "home assistant" --read --ips 192.168.1.0/24
aegis keys create "everything" --full --apps all
aegis keys list
aegis keys disable "deploy bot"      # and: enable, roll, revoke, revoke --all
aegis keys off                       # the whole API, every key refused (aegis keys on)
aegis keys log                       # what the keys did`,
};
function examplesView() {
  const b = base();
  return `<div class="seg" style="margin-bottom:10px">${[["curl", "curl"], ["node", "Node.js"], ["python", "Python"], ["cli", "Command line"]]
      .map(([k, l]) => `<button type="button" data-dv="ex" data-v="${k}" class="${DV.ex === k ? "on" : ""}">${l}</button>`).join("")}</div>
    <div class="dv-ex"><button type="button" class="btn sm dv-ex-copy" data-dv="copy" data-v="${h(EX[DV.ex](b))}">Copy</button><pre class="dv-code">${h(EX[DV.ex](b))}</pre></div>
    <div class="note-box small"><p><b>How it works</b></p>
      <ul class="dv-ul">
        <li>Send the key as <span class="mono">Authorization: Bearer aegis_…</span> or <span class="mono">X-Aegis-Key: aegis_…</span>. Never in a link: links end up in logs and histories.</li>
        <li>Everything lives under <span class="mono">${h(b)}</span>: the same calls as <span class="mono">aegis</span> on this machine (tunnels, addons, domains, updates, themes, the shield…), plus the dashboard's own (machines, notices, integrations). <span class="mono">GET /</span> lists the basics.</li>
        <li>Answers are JSON. Errors come as <span class="mono">{"error": "…"}</span> with 400/401/403/404/429. 403 with <span class="mono">need</span> says which scope was missing.</li>
        <li>With the <b>Apps</b> scope, the same header opens tunnels set to "login" and apps under the dashboard. Aegis takes the key off before the app sees the request.</li>
        <li>Keys can't see or make keys, or change your login, so a leaked key can't lock you out. Every change a key makes is in Settings → Activity with its name.</li>
      </ul>
      <p class="faint">Full reference: <a class="link" href="https://github.com/alexd-aero/aegis-burrow/blob/main/docs/API.md" target="_blank" rel="noopener">docs/API.md</a> · ready-made clients: <a class="link" href="https://github.com/alexd-aero/aegis-burrow/tree/main/examples/api" target="_blank" rel="noopener">examples/api</a></p></div>`;
}

function logView() {
  const log = DV.data.log || [];
  if (!log.length) return '<p class="muted">Nothing yet. Keys made, changed and revoked show here, and every change a key makes, and every refused call.</p>';
  return `<div class="scroll"><table><thead><tr><th>When</th><th>Key</th><th>What</th><th>From</th><th></th></tr></thead><tbody>${log.map((e) => `<tr>
      <td class="faint mono small">${h(new Date(e.t).toLocaleString())}</td><td><b>${h(e.name)}</b></td>
      <td class="mono small">${h(e.event)}${e.by ? ` <span class="faint">by ${h(e.by)}</span>` : ""}</td>
      <td class="mono small">${h(e.ip || "")}</td><td>${e.status ? `<span class="pill ${e.status < 400 ? "ok" : "err"}">${e.status}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

// ------------------------------------------------------------------ actions
async function submitForm() {
  const editing = !!DV.edit, f = editing ? DV.edit : DV.form;
  const body = { name: f.name, note: f.note, scopes: scopesOf(f), apps: f.appsMode === "all" ? "all" : f.apps, ips: f.ips, rate: f.rate === "" ? 600 : Number(f.rate) };
  if (f.expires !== "keep") body.expires = f.expires || null;
  DV.busy = true; DV.formErr = ""; DV.rerender();
  try {
    if (editing) { DV.data = await call(`/__gate/api/devkeys/${f.id}`, { method: "PATCH", body: JSON.stringify(body) }); DV.edit = null; toast("Saved"); }
    else { DV.data = await call("/__gate/api/devkeys", { method: "POST", body: JSON.stringify(body) }); DV.made = DV.data.made; DV.form = null; }
  } catch (e) { DV.formErr = e.message; }
  DV.busy = false; DV.rerender();
  if (DV.made) document.getElementById("keySecret")?.select();
}
async function play() {
  const p = DV.pg;
  let path = p.path.trim() || "/";
  if (!path.startsWith("/")) path = "/" + path;
  let body;
  if (p.method !== "GET" && p.method !== "DELETE") {
    body = p.body.trim() || "{}";
    try { JSON.parse(body); } catch { toast("The body isn't valid JSON"); return; }
  }
  p.busy = true; DV.rerender();
  const t0 = performance.now();
  try {
    const r = await fetch("/__gate/v1" + path, { method: p.method, credentials: "same-origin", headers: { "X-Gate": "1", "Content-Type": "application/json" }, body });
    const raw = await r.text();
    let text = raw;
    try { text = JSON.stringify(JSON.parse(raw), null, 2); } catch { /* not JSON */ }
    p.out = { status: r.status, method: p.method, path, ms: Math.round(performance.now() - t0), size: raw.length, text: text.length > 200000 ? text.slice(0, 200000) + "\n… (cut)" : text };
  } catch (e) { p.out = { status: 0, method: p.method, path, ms: 0, size: 0, text: e.message }; }
  p.busy = false; DV.rerender();
}
const copy = (v) => navigator.clipboard?.writeText(v).then(() => toast("Copied"), () => toast("Couldn't copy: select it and copy by hand"));

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-dv]");
  if (!el) return;
  const act = el.dataset.dv, f = DV.edit || DV.form, id = el.dataset.id;
  const key = id && DV.data?.keys.find((k) => k.id === id);
  if (act !== "copy") document.activeElement?.blur?.();      // Settings never repaints under a focused field
  try {
    if (act === "tab") { DV.tab = el.dataset.v; DV.edit = null; DV.formErr = ""; DV.rerender(); }
    else if (act === "copy") copy(el.dataset.v);
    else if (act === "preset") { f.preset = el.dataset.v; if (f.preset === "custom" && !f.scopes.length) f.scopes = ["read"]; DV.rerender(); }
    else if (act === "apps-mode") { f.appsMode = el.dataset.v; DV.rerender(); }
    else if (act === "expires") { f.expires = el.dataset.v; DV.rerender(); }
    else if (act === "edit") { DV.edit = formOf(key); DV.formErr = ""; DV.rerender(); }
    else if (act === "edit-cancel") { DV.edit = null; DV.formErr = ""; DV.rerender(); }
    else if (act === "made-done") { DV.made = null; DV.tab = "keys"; DV.rerender(); }
    else if (act === "toggle") {
      DV.data = await call(`/__gate/api/devkeys/${id}`, { method: "PATCH", body: JSON.stringify({ disabled: !key.disabled }) });
      toast(key.disabled ? `${key.name} works again` : `${key.name} switched off`); DV.rerender();
    }
    else if (act === "roll") {
      if (!confirm(`Roll ${key.name}? It gets a new secret, and the old one stops working right away: whatever uses it needs the new one.`)) return;
      DV.data = await call(`/__gate/api/devkeys/${id}/roll`, { method: "POST", body: "{}" }); DV.made = { ...DV.data.made, rolled: true }; DV.rerender();
    }
    else if (act === "revoke") {
      if (!confirm(`Revoke ${key.name}? Anything using it is refused from now on. This can't be undone.`)) return;
      DV.data = await call(`/__gate/api/devkeys/${id}`, { method: "DELETE" }); toast(`${key.name} revoked`); DV.rerender();
    }
    else if (act === "revoke-all") {
      if (!confirm("Revoke every API key? Every script and app using one is refused from now on.")) return;
      DV.data = await call("/__gate/api/devkeys/revoke-all", { method: "POST", body: "{}" }); toast("Every key revoked"); DV.rerender();
    }
    else if (act === "quick") { DV.pg.method = el.dataset.m; DV.pg.path = el.dataset.p; play(); }
    else if (act === "as-curl") {
      const p = DV.pg, b = p.method !== "GET" && p.method !== "DELETE" && p.body.trim() ? ` \\\n  -H "Content-Type: application/json" -d '${p.body.trim().replace(/'/g, "'\\''")}'` : "";
      copy(`curl -s${p.method === "GET" ? "" : ` -X ${p.method}`} ${base()}${p.path.startsWith("/") ? p.path : "/" + p.path} \\\n  -H "Authorization: Bearer $AEGIS_KEY"${b}`);
    }
    else if (act === "ex") { DV.ex = el.dataset.v; DV.rerender(); }
  } catch (ex) { toast(ex.message); loadDev(); }
});

export function wireDev(rerender) {
  DV.rerender = rerender;
  if (!DV.data && !DV.loading) { DV.loading = true; loadDev().finally(() => { DV.loading = false; }); }
  const f = DV.edit || DV.form;
  const bind = (id, k) => document.getElementById(id)?.addEventListener("input", (e) => { if (f) f[k] = e.target.value; });
  bind("dvName", "name"); bind("dvNote", "note"); bind("dvRate", "rate"); bind("dvIps", "ips");
  document.querySelectorAll("[data-dvsc]").forEach((x) => x.addEventListener("change", () => {
    const s = x.dataset.dvsc; f.scopes = x.checked ? [...new Set([...f.scopes, s])] : f.scopes.filter((y) => y !== s);
    x.blur(); DV.rerender();                                  // the apps picker comes and goes with the Apps scope
  }));
  document.querySelectorAll("[data-dvapp]").forEach((x) => x.addEventListener("change", () => {
    const a = x.dataset.dvapp; f.apps = x.checked ? [...new Set([...f.apps, a])] : f.apps.filter((y) => y !== a);
  }));
  document.getElementById("dvForm")?.addEventListener("submit", (e) => { e.preventDefault(); submitForm(); });
  document.getElementById("dvOn")?.addEventListener("change", async (e) => {
    try { DV.data = await call("/__gate/api/devkeys/enabled", { method: "POST", body: JSON.stringify({ on: e.target.checked }) }); toast(DV.data.enabled ? "API on" : "API off: every key is refused"); }
    catch (ex) { toast(ex.message); }
    DV.rerender();
  });
  document.getElementById("dvMethod")?.addEventListener("change", (e) => { DV.pg.method = e.target.value; DV.rerender(); });
  document.getElementById("dvPath")?.addEventListener("input", (e) => { DV.pg.path = e.target.value; });
  document.getElementById("dvBody")?.addEventListener("input", (e) => { DV.pg.body = e.target.value; });
  document.getElementById("dvPlay")?.addEventListener("submit", (e) => { e.preventDefault(); play(); });
}
// a fresh copy (last used, activity) with each settings poll, unless something is open
export function refreshDev() { if (DV.data && !DV.made && !DV.edit && DV.tab !== "new" && !DV.busy) loadDev(); }
