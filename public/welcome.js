// First run, after the login exists: Burrow is built in (and can go), and
// the full pack (Selkies Forge, Termix with its own login, Burrow) is offered,
// each part optional, or not at all.
import { $, h, api, post, toast } from "./common.js";

const app = $("#app");
const S = { pick: { forge: true, termix: true, burrow: true }, status: null, poll: null };

const ICON = {
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M7 7l10 10M17 7 7 17"/></svg>',
  arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
};

const PARTS = [
  { id: "forge", logo: "/__gate/logos/forge.svg", name: "Selkies Forge", text: "Linux desktops in your browser: 150+ to pick from, started in Docker, opened from here." },
  { id: "termix", logo: "/__gate/logos/termix.svg", name: "Termix", text: "SSH terminals, a file manager and saved hosts in the browser. One Docker container, only reachable through this gate." },
  { id: "burrow", logo: "/__gate/logos/burrow.svg", name: "Burrow", text: "Publish any port on its own HTTPS address, behind this login, with live traffic. Comes with Aegis.", builtin: true },
];

function head(sub) {
  return `<div class="hello"><img class="hello-logo" src="/__gate/logos/aegis-burrow.svg" alt="" width="40" height="40">
    <div><b>You're in</b><span>${h(sub)}</span></div><a class="btn ghost sm" href="/">Skip to the dashboard</a></div>`;
}

function picker() {
  const st = S.status || {};
  const card = (p) => {
    const have = p.id === "forge" ? st.forge : p.id === "termix" ? st.termix : false;
    const on = S.pick[p.id];
    return `<button type="button" class="card pk${on ? " on" : ""}" data-pick="${p.id}" aria-pressed="${on}">
      <span class="pk-tick" aria-hidden="true">${ICON.check}</span>
      <img class="pk-logo" src="${p.logo}" alt="" width="52" height="52">
      <b>${h(p.name)}${p.builtin ? ' <span class="pill">built in</span>' : ""}${have ? ' <span class="pill ok">installed</span>' : ""}</b>
      <span>${h(p.text)}</span>
    </button>`;
  };
  app.innerHTML = `${head("Set up your gate")}
    <section class="card lit note-card">
      <img src="/__gate/logos/burrow.svg" alt="" width="44" height="44">
      <div><b>Burrow comes with Aegis</b>
      <p>It gives any port its own HTTPS address behind this login. It's on by default; untick it below to remove it, or switch it off later under <span class="mono">Settings → Modules</span>.</p></div>
    </section>
    <div class="pk-head"><h1>Install the full pack?</h1><p>Everything you need on one machine, behind one post-quantum login. Untick what you don't want.</p></div>
    <div class="pk-grid">${PARTS.map(card).join("")}</div>
    <form class="card lit pk-termix${S.pick.termix && !st.termix ? "" : " gone"}" id="tx" autocomplete="off">
      <img src="/__gate/logos/termix.svg" alt="" width="36" height="36">
      <div class="grow"><b>Your Termix login</b><p>Termix has its own accounts. This one is created for you and becomes Termix's admin.</p>
        <div class="row flexwrap">
          <label class="field grow"><span>Username</span><input class="input" id="txUser" autocomplete="off" spellcheck="false" autocapitalize="none" value="${h(S.txUser || "")}"></label>
          <label class="field grow"><span>Password <span class="faint">(8+)</span></span><input class="input" id="txPass" type="password" autocomplete="new-password"></label>
        </div></div>
    </form>
    <div class="err-msg" id="pkErr"></div>
    <div class="pk-actions">
      <button class="btn primary big" id="pkGo">Install the pack</button>
      <button class="btn ghost" id="pkSkip">I don't want to install this pack</button>
    </div>`;
  const go = $("#pkGo");
  const none = !S.pick.forge && !(S.pick.termix && !st.termix) ;
  go.textContent = none ? "Continue" : "Install the pack";
}

function progress() {
  const j = S.status.job;
  const row = (s) => `<div class="card pr ${s.state}">
      <span class="pr-ic">${s.state === "done" ? ICON.check : s.state === "error" ? ICON.x : s.state === "running" ? '<i class="spin"></i>' : ""}</span>
      <div class="grow"><b>${h(s.label)}</b>${s.error ? `<span class="err-msg">${h(s.error)}</span>` : ""}
        ${s.lines.length ? `<pre class="log">${h(s.lines.join("\n"))}</pre>` : ""}</div></div>`;
  const done = j.state !== "running";
  app.innerHTML = `${head(done ? "All set" : "Setting things up")}
    <div class="pk-head"><h1>${done ? (j.state === "done" ? "Your pack is ready" : "Mostly done") : "Installing your pack…"}</h1>
      <p>${done ? "Everything below can be changed later in Settings." : "This page follows along; you can also leave and come back."}</p></div>
    <div class="pr-list">${j.steps.map(row).join("")}</div>
    ${done ? `<div class="pk-actions"><a class="btn primary big" href="/">Go to the dashboard ${ICON.arrow}</a></div>` : ""}`;
}

async function load() {
  try { S.status = await api("/__gate/api/pack"); } catch (e) { toast(e.message); return; }
  if (S.status.job) { progress(); if (S.status.job.state === "running") { clearTimeout(S.poll); S.poll = setTimeout(load, 1500); } return; }
  if (S.status.decided && !new URLSearchParams(location.search).has("again")) { location.replace("/"); return; }
  picker();
}

document.addEventListener("click", async (e) => {
  const p = e.target.closest("[data-pick]");
  if (p) { S.txUser = $("#txUser")?.value; S.pick[p.dataset.pick] = !S.pick[p.dataset.pick]; picker(); return; }
  if (e.target.closest("#pkSkip")) {
    await post("/__gate/api/pack", { skip: true }).catch((ex) => toast(ex.message));
    location.replace("/");
    return;
  }
  const go = e.target.closest("#pkGo");
  if (!go) return;
  const err = $("#pkErr"); err.textContent = "";
  const st = S.status || {};
  const choice = { burrow: S.pick.burrow, forge: S.pick.forge && !st.forge, termix: null };
  if (S.pick.termix && !st.termix) {
    const username = $("#txUser").value.trim(), password = $("#txPass").value;
    if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) { err.textContent = "Termix username: 2-64 letters, digits, . _ @ -"; return; }
    if (password.length < 8) { err.textContent = "Termix password: at least 8 characters."; return; }
    choice.termix = { username, password };
  }
  go.disabled = true; go.innerHTML = '<i class="spin"></i> Starting…';
  try {
    if (!window.AegisSeal) throw new Error("The sealing code did not load. Reload the page.");
    // the Termix password travels sealed, like the gate's own login
    await api("/__gate/api/pack", { method: "POST", body: JSON.stringify(await window.AegisSeal(choice)) });
    load();
  } catch (ex) { err.textContent = ex.message; go.disabled = false; go.textContent = "Install the pack"; }
});

load();
