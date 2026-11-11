// The core host script (Weft spec §12.5). Aegis puts it at the top of every
// signed-in page, whatever theme is in use; a theme can't replace it. It:
//   - catches a theme's errors, and if a page breaks, offers the default look;
//   - in a preview frame, reports how the page did to the page around it;
//   - draws your background (a picture, a GIF or a video) behind themes that have one;
//   - runs a theme's welcome once it is applied: your background first, then
//     the theme's own steps. window.WeftHost opens the picker any time.
// Classic script, no imports: it must run before anything else on the page.
(() => {
  "use strict";
  const el = document.getElementById("weft-host");
  if (!el || window.WeftHost) return;
  let C;
  try { C = JSON.parse(el.textContent); } catch { return; }
  const T = C.theme, t0 = performance.now(), errors = [];
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SAVE = !!navigator.connection?.saveData;

  // ---------------------------------------------------------- errors
  addEventListener("error", (e) => { if (e instanceof ErrorEvent) errors.push(`${e.message || "error"}${e.filename ? ` (${e.filename.replace(location.origin, "").split("?")[0]}:${e.lineno})` : ""}`.slice(0, 300)); });
  addEventListener("unhandledrejection", (e) => { const r = e.reason; errors.push(`unhandled: ${r?.message || String(r)}`.slice(0, 300)); });

  const h = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const api = async (path, opts = {}) => {
    const r = await fetch(path, { credentials: "same-origin", ...opts, headers: { ...(opts.body && !(opts.body instanceof Blob) ? { "Content-Type": "application/json" } : {}), "X-Gate": "1", ...(opts.headers || {}) } });
    const type = r.headers.get("content-type") || "";
    if (!type.includes("json")) { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r; }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), j);
    return j;
  };
  const drew = () => {
    const main = document.querySelector("#app, main, .home-in, body");
    return !!main && (main.innerText || "").trim().length > 20;
  };

  // ---------------------------------------------------------- a preview frame reports back
  if (C.preview) {
    document.documentElement.classList.add("weft-previewing");
    addEventListener("load", () => {
      setTimeout(() => {
        const page = (location.pathname.match(/\/page\/(\w+)/) || [])[1] || "page";
        const msg = { type: "weft-theme-run", page, errors: errors.length, list: errors.slice(0, 8), ms: Math.round(performance.now() - t0), ok: drew() };
        try { parent.postMessage(msg, location.origin); } catch { /* not framed */ }
      }, 2600);
    });
  }

  // ---------------------------------------------------------- the way out when a theme breaks a page
  if (T && !C.preview) {
    addEventListener("load", () => setTimeout(() => {
      if (!errors.length) return;
      try { if (sessionStorage.getItem("weft-bar-" + T.id) === "x") return; } catch { /* private mode */ }
      const empty = !drew();
      const bar = document.createElement("div");
      bar.className = "wh-bar" + (empty ? " bad" : "");
      bar.setAttribute("role", "alert");
      bar.innerHTML = `<span><b>${h(T.name)}</b> ${empty ? "didn't draw this page" : `hit ${errors.length === 1 ? "an error" : `${errors.length} errors`} here`}.</span>
        <button type="button" data-wh="why">Why</button><a href="/__gate/theme-off">Use the default look</a><button type="button" data-wh="x" aria-label="Dismiss">×</button>`;
      bar.addEventListener("click", (e) => {
        const b = e.target.closest("[data-wh]");
        if (!b) return;
        if (b.dataset.wh === "why") alert(errors.join("\n"));
        if (b.dataset.wh === "x") { try { sessionStorage.setItem("weft-bar-" + T.id, "x"); } catch { /* */ } bar.remove(); }
      });
      document.body.append(bar);
    }, 4500));
  }

  // ---------------------------------------------------------- backgrounds
  const src = (id, f) => `/__gate/backdrops/${id}${f}`;
  let media = C.media, pick = C.background;
  function paintBackground() {
    if (!T?.backgrounds) return;
    const kind = pick?.startsWith("theme:") ? pick.slice(6) : pick?.startsWith("img:") && media ? "media" : T.backgrounds.default || "none";
    document.documentElement.dataset.bg = kind;
    if (!document.body) return;
    let bg = document.querySelector(".weft-bg");
    if (!bg) {
      bg = document.createElement("div");
      bg.className = "weft-bg";
      bg.setAttribute("aria-hidden", "true");
      bg.innerHTML = '<div class="weft-bg-theme"></div><div class="weft-bg-media"></div>';
      document.body.prepend(bg);
    }
    const box = bg.querySelector(".weft-bg-media");
    const cur = box.firstElementChild;
    if (kind !== "media") { box.dataset.id = ""; cur?.classList.remove("on"); setTimeout(() => { if (box.dataset.id === "") box.textContent = ""; }, 900); return; }
    if (box.dataset.id === media.id) return;
    box.dataset.id = media.id;
    box.style.setProperty("--weft-tiny", media.poster ? `url(${src(media.id, "-t.jpg")})` : "none");
    let node;
    if (media.kind === "video" && !REDUCED && !SAVE) {
      node = document.createElement("video");
      Object.assign(node, { muted: true, loop: true, autoplay: true, playsInline: true, src: src(media.id, "." + media.ext) });
      node.setAttribute("muted", ""); node.setAttribute("playsinline", "");
      if (media.poster) node.poster = src(media.id, "-t.jpg");
      node.addEventListener("loadeddata", () => node.classList.add("on"), { once: true });
    } else {
      node = new Image();
      node.alt = ""; node.decoding = "async";
      if (media.kind === "image") { node.srcset = `${src(media.id, "-s.jpg")} 1280w, ${src(media.id, "-l.jpg")} 3840w`; node.sizes = "100vw"; }
      else if (media.kind === "gif" && !REDUCED) node.src = src(media.id, ".gif");
      else node.src = src(media.id, "-t.jpg");
      node.addEventListener("load", () => node.classList.add("on"), { once: true });
    }
    box.append(node);
    if (cur) setTimeout(() => cur.remove(), 1200);
  }
  if (T?.backgrounds) {
    document.documentElement.classList.add("weft-has-bg");
    paintBackground();                                    // html[data-bg] now, before the page paints
    document.addEventListener("DOMContentLoaded", paintBackground, { once: true });
  }
  async function setBackground(p, entry = null) {
    await api("/__gate/api/backdrops/pick", { method: "POST", body: JSON.stringify({ pick: p }) });
    pick = p;
    if (p.startsWith("img:")) media = entry || (await api("/__gate/api/backdrops")).backdrops.find((b) => b.id === p.slice(4)) || null;
    paintBackground();
    dispatchEvent(new CustomEvent("weft:background", { detail: { pick: p, media } }));
  }

  // ---------------------------------------------------------- making the sizes, here (Aegis has no image library)
  async function bitmapOf(blob) { return createImageBitmap(blob); }
  const canvasOf = (src, w) => {
    const sw = src.videoWidth || src.width, sh = src.videoHeight || src.height, k = Math.min(1, w / sw);
    const c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(sw * k)); c.height = Math.max(1, Math.round(sh * k));
    c.getContext("2d").drawImage(src, 0, 0, c.width, c.height);
    return c;
  };
  async function sizesOf(blob, name, source) {
    const bmp = await bitmapOf(blob);
    const out = { name, source, w: Math.min(bmp.width, 3840), h: Math.round(Math.min(bmp.width, 3840) * bmp.height / bmp.width),
                  l: canvasOf(bmp, 3840).toDataURL("image/jpeg", 0.85), s: canvasOf(bmp, 1280).toDataURL("image/jpeg", 0.8), t: canvasOf(bmp, 40).toDataURL("image/jpeg", 0.7) };
    bmp.close?.();
    return out;
  }
  // the still a GIF or a video shows while it loads
  async function posterOf(url, kind) {
    try {
      if (kind === "gif") { const bmp = await bitmapOf(await (await fetch(url)).blob()); const r = { t: canvasOf(bmp, 40).toDataURL("image/jpeg", 0.7), w: bmp.width, h: bmp.height }; bmp.close?.(); return r; }
      const v = document.createElement("video");
      v.muted = true; v.preload = "auto"; v.src = url;
      await new Promise((ok, bad) => { v.addEventListener("loadeddata", ok, { once: true }); v.addEventListener("error", bad, { once: true }); setTimeout(bad, 15000); });
      v.currentTime = Math.min(0.5, (v.duration || 1) / 4);
      await new Promise((ok) => { v.addEventListener("seeked", ok, { once: true }); setTimeout(ok, 3000); });
      return { t: canvasOf(v, 40).toDataURL("image/jpeg", 0.7), w: v.videoWidth, h: v.videoHeight };
    } catch { return null; }
  }
  async function addFile(file) {
    const name = file.name.replace(/\.[a-z0-9]+$/i, "").replace(/[-_]+/g, " ").slice(0, 60);
    if (/svg/i.test(file.type) || /\.svg$/i.test(file.name)) throw new Error("SVG pictures can carry scripts, so they can't be backgrounds.");
    if (/^image\/gif$/i.test(file.type) || /^video\//i.test(file.type)) {
      const e = await api(`/__gate/api/backdrops/raw?name=${encodeURIComponent(name)}`, { method: "POST", body: file, headers: { "Content-Type": file.type || "application/octet-stream" } });
      const p = await posterOf(src(e.id, "." + e.ext), e.kind);
      return p ? api(`/__gate/api/backdrops/${e.id}/poster`, { method: "PUT", body: JSON.stringify(p) }) : e;
    }
    return api("/__gate/api/backdrops", { method: "POST", body: JSON.stringify(await sizesOf(file, name)) });
  }
  async function addLink(url, label = "") {
    const r = await api("/__gate/api/backdrops/link", { method: "POST", body: JSON.stringify({ url, name: label }) });
    if (!(r instanceof Response)) {                  // a GIF or a video, kept as it is
      const p = await posterOf(src(r.id, "." + r.ext), r.kind);
      return p ? api(`/__gate/api/backdrops/${r.id}/poster`, { method: "PUT", body: JSON.stringify(p) }) : r;
    }
    const name = decodeURIComponent(r.headers.get("X-Backdrop-Name") || "Picture"), source = decodeURIComponent(r.headers.get("X-Backdrop-Source") || url);
    return api("/__gate/api/backdrops", { method: "POST", body: JSON.stringify(await sizesOf(await r.blob(), name, source)) });
  }

  // ---------------------------------------------------------- the welcome (and the picker)
  const ICON = {
    up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M7 9l5-5 5 5M5 20h14"/></svg>',
    link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>',
    play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>',
  };
  const W = { open: false, step: 0, steps: [], mine: null, busy: {}, filter: "all", err: "", slide: 0 };
  function stepsFor(only) {
    if (only === "background") return [{ kind: "background" }];
    const s = [{ kind: "hello" }];
    if (T.backgrounds) s.push({ kind: "background" });
    for (const x of T.onboarding || []) s.push({ kind: "theme", ...x });
    s.push({ kind: "done" });
    return s;
  }
  async function open(only = null) {
    if (!T || W.open) return;
    W.open = true; W.step = 0; W.steps = stepsFor(only); W.only = only; W.err = "";
    const scrim = document.createElement("div");
    scrim.className = "wh-scrim";
    scrim.innerHTML = `<div class="wh-modal" role="dialog" aria-modal="true" aria-label="${h(T.name)}" style="${T.accent ? `--wh-accent:${T.accent}` : ""}"></div>`;
    document.body.append(scrim);
    W.scrim = scrim;
    scrim.addEventListener("click", onClick);
    scrim.addEventListener("change", onChange);
    scrim.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.id === "whLink") { e.preventDefault(); scrim.querySelector('[data-wh="link"]')?.click(); } });
    document.addEventListener("keydown", onKey);
    paint();
    if (T.backgrounds) { try { W.mine = (await api("/__gate/api/backdrops")).backdrops; } catch { W.mine = []; } paint(); }
  }
  function close(done) {
    if (!W.open) return;
    W.open = false;
    W.scrim?.classList.add("out");
    setTimeout(() => W.scrim?.remove(), 260);
    document.removeEventListener("keydown", onKey);
    if (done && !W.only) api("/__gate/api/themes/onboarded", { method: "POST", body: JSON.stringify({ id: T.id }) }).catch(() => {});
  }
  const onKey = (e) => { if (e.key === "Escape") close(true); if (e.key === "ArrowRight" && W.steps[W.step]?.kind !== "background" && !/INPUT/.test(document.activeElement?.tagName)) go(1); };
  function go(d) { W.step = Math.max(0, Math.min(W.steps.length - 1, W.step + d)); W.err = ""; paint(true); }
  function dots() { return W.steps.length < 2 ? "" : `<div class="wh-dots">${W.steps.map((_, i) => `<i class="${i === W.step ? "on" : i < W.step ? "past" : ""}"></i>`).join("")}</div>`; }
  function nav(nextLabel = "Next") {
    const last = W.step === W.steps.length - 1;
    return `<div class="wh-foot">${dots()}<span class="wh-grow"></span>
      ${W.step > 0 && !W.only ? '<button type="button" class="wh-btn ghost" data-wh="back">Back</button>' : ""}
      ${W.only ? '<button type="button" class="wh-btn" data-wh="close">Done</button>' : last ? '<button type="button" class="wh-btn" data-wh="finish">Start using it</button>' : `<button type="button" class="wh-btn" data-wh="next">${nextLabel}</button>`}</div>`;
  }
  function tileOf(b) {
    const on = pick === `img:${b.id}`, still = b.poster ? src(b.id, "-t.jpg") : null;
    const img = b.kind === "image" ? src(b.id, "-s.jpg") : b.kind === "gif" ? src(b.id, ".gif") : still;
    return `<div class="wh-tile${on ? " on" : ""}" role="button" tabindex="0" data-pick="img:${h(b.id)}" title="${h(b.name)}">
      ${img ? `<img src="${h(img)}" alt="" loading="lazy">` : ""}${b.kind === "video" ? `<span class="wh-kind">${ICON.play} video</span>` : b.kind === "gif" ? '<span class="wh-kind">GIF</span>' : ""}
      <span class="wh-name">${h(b.name)}</span>${on ? `<span class="wh-on">${ICON.check}</span>` : ""}
      <button type="button" class="wh-del" data-del="${h(b.id)}" title="Remove from this machine" aria-label="Remove ${h(b.name)}">${ICON.x}</button></div>`;
  }
  function backgroundStep() {
    const B = T.backgrounds, rec = B.recommended || [];
    const tags = [...new Set(rec.flatMap((r) => r.tags))].slice(0, 10);
    const shown = rec.filter((r) => W.filter === "all" || r.tags.includes(W.filter));
    const mineUrls = new Set((W.mine || []).map((b) => b.source).filter(Boolean));
    return `<div class="wh-head"><span class="wh-k">${W.only ? h(T.name) : `Step ${W.step + 1} of ${W.steps.length}`}</span><h2>Pick your background</h2>
        <p>Behind every page. Your pictures stay on this machine; they never go into the theme or Aegis.</p></div>
      <div class="wh-scroll">
        ${B.builtin.length ? `<div class="wh-sec"><span class="wh-k">Built into ${h(T.name)}</span><div class="wh-grid">${B.builtin.map((b) => `<div class="wh-tile sw${pick === `theme:${b.id}` ? " on" : ""}" role="button" tabindex="0" data-pick="theme:${h(b.id)}" style="background:${h(b.swatch)}">
          <span class="wh-name">${h(b.name)}</span>${pick === `theme:${b.id}` ? `<span class="wh-on">${ICON.check}</span>` : ""}</div>`).join("")}</div></div>` : ""}
        ${rec.length ? `<div class="wh-sec"><div class="wh-row"><span class="wh-k">Recommended by ${h(T.name)}</span><span class="wh-grow"></span>
            ${tags.length > 1 ? `<div class="wh-chips">${["all", ...tags].map((t) => `<button type="button" class="${W.filter === t ? "on" : ""}" data-tag="${h(t)}">${h(t === "all" ? "All" : t)}</button>`).join("")}</div>` : ""}</div>
          <div class="wh-grid">${shown.map((r) => { const have = mineUrls.has(r.url), busy = W.busy[r.url];
            return `<div class="wh-tile rec${have ? " have" : ""}" role="button" tabindex="0" data-rec="${h(r.url)}" title="${h(r.name)}${r.tags.length ? ` · ${h(r.tags.join(", "))}` : ""}">
              ${r.preview ? `<img src="${h(r.preview)}" alt="" loading="lazy">` : `<span class="wh-ph">${h(r.name[0])}</span>`}
              <span class="wh-name">${h(r.name)}</span>${busy ? '<span class="wh-busy"><i class="wh-spin"></i>Getting it…</span>' : have ? '<span class="wh-kind">yours</span>' : ""}</div>`; }).join("")}</div></div>` : ""}
        <div class="wh-sec"><span class="wh-k">Yours</span>
          <div class="wh-grid">${W.mine == null ? '<span class="wh-muted"><i class="wh-spin"></i> Loading…</span>' : (W.mine.map(tileOf).join("") || "")}
            <label class="wh-tile add${W.busy.upload ? " busy" : ""}"><input type="file" id="whFile" accept="image/*,video/mp4,video/webm" hidden ${W.busy.upload ? "disabled" : ""}>
              ${W.busy.upload ? '<i class="wh-spin"></i><span>Adding…</span>' : `${ICON.up}<span>Upload</span><small>picture, GIF or video</small>`}</label></div>
          <div class="wh-link">${ICON.link}<input id="whLink" type="url" placeholder="Paste a link: a wallpaperflare page, a picture, a GIF or a video" autocomplete="off" spellcheck="false">
            <button type="button" class="wh-btn sm" data-wh="link" ${W.busy.link ? "disabled" : ""}>${W.busy.link ? '<i class="wh-spin"></i> Getting it' : "Add"}</button></div>
          ${W.err ? `<p class="wh-err" role="alert">${h(W.err)}</p>` : ""}</div>
      </div>${nav("Next")}`;
  }
  function paint(moved = false) {
    if (!W.open) return;
    const m = W.scrim.querySelector(".wh-modal"), s = W.steps[W.step];
    const keepLink = m.querySelector("#whLink")?.value || "";
    const scroll = m.querySelector(".wh-scroll")?.scrollTop || 0;
    let html;
    if (s.kind === "hello") {
      const pv = T.previews || [];
      W.slide = Math.min(W.slide, Math.max(0, pv.length - 1));
      html = `<div class="wh-hero">${pv.length ? `<div class="wh-shots">${pv.map((p, i) => `<img src="${h(p.url)}" alt="${h(p.caption || T.name)}" class="${i === W.slide ? "on" : ""}">`).join("")}</div>
          ${pv.length > 1 ? `<div class="wh-thumbs">${pv.map((p, i) => `<button type="button" class="${i === W.slide ? "on" : ""}" data-slide="${i}">${h(p.caption || `View ${i + 1}`)}</button>`).join("")}</div>` : ""}` : ""}</div>
        <div class="wh-head"><span class="wh-k">Theme applied</span><h2>Welcome to ${h(T.name)}</h2>
          <p>${h(T.description || "Your dashboard has a new look.")}</p>
          <p class="wh-muted">${h(T.name)} ${h(T.version)}${T.author ? ` · by ${h(T.author)}` : ""} · Settings → Themes brings back the default look any time.</p></div>${nav(T.backgrounds ? "Pick a background" : "Next")}`;
    } else if (s.kind === "background") html = backgroundStep();
    else if (s.kind === "theme") {
      html = `${s.image ? `<div class="wh-hero"><div class="wh-shots"><img class="on" src="${h(s.image)}" alt=""></div></div>` : ""}
        <div class="wh-head"><span class="wh-k">${h(T.name)} · ${W.step + 1} of ${W.steps.length}</span><h2>${h(s.title)}</h2><p>${h(s.body)}</p>
        ${s.button ? `<a class="wh-btn ghost" href="${h(s.button.href)}"${/^https:/.test(s.button.href) ? ' target="_blank" rel="noopener"' : ""}>${h(s.button.label)}</a>` : ""}</div>${nav()}`;
    } else {
      html = `<div class="wh-head center"><span class="wh-big">${ICON.check}</span><h2>You're all set</h2>
        <p>${h(T.name)} is your dashboard's look now.${T.backgrounds ? " Your background can change any time: Settings → Themes → Background." : ""}</p></div>${nav()}`;
    }
    m.innerHTML = html;
    m.dataset.step = s.kind;
    if (moved && !REDUCED) { m.classList.remove("wh-in"); void m.offsetWidth; m.classList.add("wh-in"); }
    const li = m.querySelector("#whLink"); if (li && keepLink) li.value = keepLink;
    const sc = m.querySelector(".wh-scroll"); if (sc && !moved) sc.scrollTop = scroll;
  }
  async function onClick(e) {
    if (e.target === W.scrim) return close(true);
    const t = e.target;
    const act = t.closest("[data-wh]")?.dataset.wh;
    if (act === "next") return go(1);
    if (act === "back") return go(-1);
    if (act === "finish" || act === "close") return close(true);
    const sl = t.closest("[data-slide]"); if (sl) { W.slide = Number(sl.dataset.slide); return paint(); }
    const tg = t.closest("[data-tag]"); if (tg) { W.filter = tg.dataset.tag; return paint(); }
    const del = t.closest("[data-del]");
    if (del) {
      e.stopPropagation();
      const b = (W.mine || []).find((x) => x.id === del.dataset.del);
      if (!confirm(`Remove “${b?.name || "this background"}” from this machine?`)) return;
      try { W.mine = (await api(`/__gate/api/backdrops/${del.dataset.del}`, { method: "DELETE" })).backdrops; if (pick === `img:${del.dataset.del}`) { pick = T.backgrounds.default ? `theme:${T.backgrounds.default}` : null; media = null; paintBackground(); } }
      catch (ex) { W.err = ex.message; }
      return paint();
    }
    const pk = t.closest("[data-pick]");
    if (pk) {
      try { await setBackground(pk.dataset.pick, (W.mine || []).find((b) => `img:${b.id}` === pk.dataset.pick)); W.err = ""; } catch (ex) { W.err = ex.message; }
      return paint();
    }
    const rc = t.closest("[data-rec]");
    if (rc) {
      const url = rc.dataset.rec, have = (W.mine || []).find((b) => b.source === url);
      if (have) { await setBackground(`img:${have.id}`, have).catch((ex) => { W.err = ex.message; }); return paint(); }
      if (W.busy[url]) return;
      W.busy[url] = true; W.err = ""; paint();
      try { const b = await addLink(url, rc.title.split(" · ")[0]); W.mine = [b, ...(W.mine || [])]; await setBackground(`img:${b.id}`, b); }
      catch (ex) { W.err = `${rc.title.split(" · ")[0]}: ${ex.message}`; }
      delete W.busy[url]; return paint();
    }
    if (act === "link") {
      const url = W.scrim.querySelector("#whLink")?.value.trim();
      if (!url) { W.err = "Paste a link first."; return paint(); }
      W.busy.link = true; W.err = ""; paint();
      try { const b = await addLink(url); W.mine = [b, ...(W.mine || [])]; await setBackground(`img:${b.id}`, b); W.scrim.querySelector("#whLink").value = ""; }
      catch (ex) { W.err = ex.message; }
      W.busy.link = false; return paint();
    }
  }
  async function onChange(e) {
    if (e.target.id !== "whFile" || !e.target.files?.[0]) return;
    W.busy.upload = true; W.err = ""; paint();
    try { const b = await addFile(e.target.files[0]); W.mine = [b, ...(W.mine || [])]; await setBackground(`img:${b.id}`, b); }
    catch (ex) { W.err = ex.message || "That file didn't work."; }
    W.busy.upload = false; paint();
  }
  if (T?.welcome && !C.preview) addEventListener("load", () => setTimeout(() => open(), 700));

  window.WeftHost = Object.freeze({
    config: C, errors,
    welcome: () => open(),
    pickBackground: () => open("background"),
    setBackground, addFile, addLink,
    backgrounds: async () => (await api("/__gate/api/backdrops")).backdrops,
  });
})();
