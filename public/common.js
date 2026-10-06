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
  return me;
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
export function updHero(kind, icon, title, sub, extra = "") {
  return `<div class="uc-hero ${kind}"><div class="uc-orb">${icon}</div>
    <div class="uc-txt"><div class="uc-title">${title}</div><div class="uc-sub">${sub}</div></div>${extra}</div>`;
}
export const verJump = (from, to) => `<div class="uc-ver"><span>v${h(from)}</span>${UPD.arrow}<b>v${h(to)}</b></div>`;

// Install the update, then wait for the new version to answer and reload.
export async function runUpdate(onPhase) {
  onPhase("Downloading and installing…");
  const r = await post("/__gate/api/update/apply");
  if (r.job?.state === "error") throw new Error(r.job.error);
  if (!r.job?.to) { onPhase("Already up to date."); return; }
  if (r.scope === "manual") { onPhase(`Installed ${r.job.to}. Restart Aegis × Burrow with whatever runs it to finish.`); return; }
  onPhase(`Installed ${r.job.to}. Restarting…`);
  const t0 = Date.now();
  for (;;) {
    await new Promise((ok) => setTimeout(ok, 1500));
    try {
      const v = await fetch("/__gate/health", { cache: "no-store" }).then((x) => x.json());
      if (v.version === r.job.to) { location.reload(); return; }
    } catch { /* restarting */ }
    if (Date.now() - t0 > 120000) { onPhase("It is taking a while to come back. Reload in a minute, or run: aegis status"); return; }
  }
}

const seen = (k) => { try { return localStorage.getItem(k) === "1"; } catch { return false; } };
const hide = (k) => { try { localStorage.setItem(k, "1"); } catch { /* private window */ } };

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
