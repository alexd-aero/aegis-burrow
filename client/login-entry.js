// The sign-in and first-run pages. Bundled by esbuild into public/login.js.
//
// The credentials never leave the browser in the clear, even on plain HTTP:
//
//   ss       = X-Wing shared secret (ML-KEM-768 + X25519), server key is single-use
//   K_inner  = HKDF-SHA384(ss, salt = challenge id, "aegis/v1/inner")
//   K_outer  = HKDF-SHA384(ss, salt = challenge id, "aegis/v1/outer")
//   payload  = AES-256-GCM(K_outer, AES-256-GCM(K_inner, credentials))
//
// Everything here is pure JavaScript (noble), not WebCrypto, so it also works
// on a LAN or Tailscale address where the browser hides crypto.subtle.
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha384 } from "@noble/hashes/sha2.js";

const enc = new TextEncoder();
const b64u = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const key = (ss, id, label) => hkdf(sha384, ss, enc.encode(id), enc.encode(label), 32);

async function seal(fields) {
  const ch = await (await fetch("/__gate/challenge", { method: "POST" })).json();
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(unb64u(ch.pk));
  const kInner = key(sharedSecret, ch.id, "aegis/v1/inner");
  const kOuter = key(sharedSecret, ch.id, "aegis/v1/outer");
  sharedSecret.fill(0);
  const iv1 = rand(12);
  const inner = gcm(kInner, iv1, enc.encode("inner|" + ch.id)).encrypt(enc.encode(JSON.stringify(fields)));
  const innerMsg = new Uint8Array(12 + inner.length);
  innerMsg.set(iv1); innerMsg.set(inner, 12);
  const iv2 = rand(12);
  const outer = gcm(kOuter, iv2, enc.encode("outer|" + ch.id)).encrypt(innerMsg);
  kInner.fill(0); kOuter.fill(0);
  return { id: ch.id, ct: b64u(cipherText), iv: b64u(iv2), c: b64u(outer) };
}

// The settings page reuses the same sealing for a password change.
window.AegisSeal = seal;

const form = document.getElementById("f");
if (form) wire();

function wire() {
  const msg = document.getElementById("msg");
  const btn = document.getElementById("go");
  const pw = document.getElementById("password");
  const pw2 = document.getElementById("password2");
  const peek = document.getElementById("peek");
  const caps = document.getElementById("caps");
  const setup = document.body.dataset.mode === "setup";
  const unlock = document.body.dataset.mode === "unlock";      // a tunnel's own password: no username

  function setState(state, text = "") {
    // restart the shake animation on repeated errors
    if (state === "err") { document.body.dataset.state = "idle"; void document.body.offsetWidth; }
    document.body.dataset.state = state;
    msg.textContent = text;
  }

  peek.addEventListener("click", () => {
    const show = pw.type === "password";
    pw.type = show ? "text" : "password";
    if (pw2) pw2.type = pw.type;
    peek.setAttribute("aria-pressed", String(show));
    peek.setAttribute("aria-label", show ? "Hide password" : "Show password");
    pw.focus();
  });

  for (const ev of ["keydown", "keyup"]) {
    pw.addEventListener(ev, (e) => caps.classList.toggle("show", !!e.getModifierState?.("CapsLock")));
  }
  pw.addEventListener("blur", () => caps.classList.remove("show"));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = unlock ? "" : form.username.value.trim();
    if (unlock && !pw.value) return setState("err", "Enter the password.");
    if (!unlock && (!username || !pw.value)) return setState("err", "Enter a username and a password.");
    if (setup) {
      if (!/^[A-Za-z0-9._@-]{2,64}$/.test(username)) return setState("err", "Username: 2-64 letters, digits, . _ @ -");
      if (pw.value.length < 10) return setState("err", "Use at least 10 characters.");
      if (pw.value !== pw2.value) return setState("err", "The two passwords differ.");
    }
    btn.disabled = true;
    setState("busy", "Negotiating post-quantum channel…");
    try {
      const q = new URLSearchParams(location.search);
      const fields = setup ? { username, password: pw.value, token: q.get("t") || "" }
                   : unlock ? { password: pw.value, next: q.get("next") || "" }
                           : { username, password: pw.value, next: q.get("next") || "" };
      const sealed = await seal(fields);
      msg.textContent = setup ? "Saving…" : "Verifying…";
      const r = await fetch(setup ? "/__gate/setup" : unlock ? "/__gate/unlock" : "/__gate/auth", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(sealed),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok) { setState("ok", setup ? "You're in." : unlock ? "Unlocked." : "Access granted."); setTimeout(() => location.replace(j.next || "/"), 450); return; }
      setState("err", j.error || "Access denied.");
      pw.select();
    } catch (err) {
      setState("err", "Handshake failed: " + err.message);
    }
    btn.disabled = false;
  });
}
