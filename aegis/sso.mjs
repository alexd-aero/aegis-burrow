// Single sign-on for the dashboard: "Sign in with Google" (straight, or through
// Auth0), Microsoft Entra ID, Okta, GitHub, Robo Accounts, and any OpenID Connect,
// OAuth 2.0 or SAML 2.0 provider of your own.
//
// Aegis has one owner, so a provider never makes accounts: it proves that the
// person at the browser is the owner, or someone the owner allowed (an exact
// email, an email domain, a subject or a group). Nobody is allowed until the
// owner adds someone; a test sign-in shows what the provider sent, to add from.
// A sign-in that gets through does what the password does (gate.mjs ssoRoute).
//
// OpenID Connect and OAuth 2.0: the authorization code flow with PKCE (S256),
// state and nonce kept here, in memory, for ten minutes, and bound to the
// browser that started it (a cookie the gate sets).
//   GET /__gate/sso/<id>/start?next=…   -> the provider's authorize endpoint
//   GET /__gate/sso/<id>/callback       <- ?code&state: exchanged at the token endpoint
//   oidc    the issuer's /.well-known/openid-configuration; the id_token's signature
//           against its JWKS (cached, fetched again for a kid it doesn't know):
//           RS256/384/512, PS256, ES256/384, EdDSA; then iss, aud and azp,
//           exp/iat/nbf (2 minutes of clock skew) and the nonce
//   oauth2  no id_token (GitHub): who you are comes from the userinfo endpoint
// SAML 2.0: SP-initiated over HTTP-Redirect, the answer over HTTP-POST.
//   GET  /__gate/sso/<id>/start         -> an AuthnRequest (deflated, base64) to the IdP
//   POST /__gate/sso/<id>/acs           <- SAMLResponse: an XML signature (xml-crypto,
//        vendored in vendor/saml.mjs) on the Response or on the Assertion, by one of
//        the IdP's certificates; the identity is read only from the XML that the
//        verified signature covers, and a response with more than one assertion is
//        refused (signature wrapping). Then Issuer, Destination, Recipient, Audience,
//        NotBefore/NotOnOrAfter and InResponseTo (an unsolicited answer only when the
//        provider allows IdP-initiated sign-in); sha1 only when allowed.
//   GET  /__gate/sso/<id>/metadata      the SP metadata; its URL is the SP's entity ID
//
// settings "sso": { base, only, providers: [{ id, preset, kind, name, enabled, …,
//                   allow: { emails, domains, subjects, groups } }] }
// base: where callbacks live (default: https://<the main host>); only: hide the
// password form (gate.mjs keeps a way back in: `aegis sso password on`, or a
// one-time link from `aegis sso link`). Client secrets are sealed with the gate's
// secret.key before they are written (box, from gate.mjs).

import { randomBytes, createHash, createPublicKey, verify as cverify, sign as csign, constants as C, X509Certificate,
         hkdfSync, createCipheriv, createDecipheriv } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { SignedXml, DOMParser } from "./vendor/saml.mjs";

const SKEW_S = 120;                      // clock skew allowed either way
const FLOW_TTL_MS = 10 * 60 * 1000;      // a sign-in has ten minutes to come back
const TEST_TTL_MS = 15 * 60 * 1000;
const META_TTL_MS = 60 * 60 * 1000;      // discovery documents and JWKS
const SAML_META_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_SAML = 512 * 1024;
const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const HOST_RE = /^(?=.{1,253}(:\d{1,5})?$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/i;

const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256 = (s) => createHash("sha256").update(s).digest();
const clean = (v, n = 300) => String(v ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, n);
const xmlEsc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[c]));

// Secrets in state.json (client secrets): AES-256-GCM under a key derived from the
// gate's secret.key, so a copy of state.json alone doesn't hand them over.
export function secretBox(master) {
  const key = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(0), "aegis/sso-secrets/v1", 32));
  return {
    seal(plain) {
      const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv);
      const body = Buffer.concat([c.update(String(plain), "utf8"), c.final()]);
      return `enc1:${b64u(Buffer.concat([iv, body, c.getAuthTag()]))}`;
    },
    open(sealed) {
      try {
        const raw = Buffer.from(String(sealed).replace(/^enc1:/, ""), "base64url");
        const d = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
        d.setAuthTag(raw.subarray(raw.length - 16));
        return Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString("utf8");
      } catch { return null; }
    },
  };
}

export class SsoError extends Error {
  // code: what the sign-in page says (gate.mjs SSO_MSG): failed, denied, expired, cancelled, config, off
  constructor(msg, code = "failed", flow = null) { super(msg); this.code = code; this.flow = flow; this.status = code === "config" ? 400 : 401; }
}

// ---------------------------------------------------------------- presets
// What each kind of provider needs, pre-filled. The dashboard (public/sso.js)
// has the matching step-by-step instructions; docs/SSO.md has them too.
const LOOSE_HOST = (v) => clean(v, 260).replace(/^https?:\/\//i, "").replace(/\/+$/, "").toLowerCase();
export const PRESETS = {
  google:   { name: "Google", kind: "oidc", button: "Sign in with Google", scopes: "openid email profile", verifiedEmail: true,
              issuer: () => "https://accounts.google.com", aliases: ["accounts.google.com"], params: { prompt: "select_account" } },
  auth0:    { name: "Auth0", kind: "oidc", button: "Sign in with Auth0", scopes: "openid email profile", verifiedEmail: true, fields: ["domain"],
              issuer: (p) => `https://${p.domain}/` },
  entra:    { name: "Microsoft Entra ID", kind: "oidc", button: "Sign in with Microsoft", scopes: "openid email profile", verifiedEmail: false, fields: ["tenant"],
              issuer: (p) => `https://login.microsoftonline.com/${p.tenant}/v2.0` },
  okta:     { name: "Okta", kind: "oidc", button: "Sign in with Okta", scopes: "openid email profile", verifiedEmail: true, fields: ["domain", "authServer"],
              issuer: (p) => (p.authServer ? `https://${p.domain}/oauth2/${p.authServer}` : `https://${p.domain}`) },
  github:   { name: "GitHub", kind: "oauth2", button: "Sign in with GitHub", scopes: "read:user user:email", verifiedEmail: true,
              authorizeUrl: "https://github.com/login/oauth/authorize", tokenUrl: "https://github.com/login/oauth/access_token",
              userinfoUrl: "https://api.github.com/user", emailsUrl: "https://api.github.com/user/emails" },
  robo:     { name: "Robo Accounts", kind: "oidc", button: "Sign in with Robo Accounts", scopes: "openid email profile", verifiedEmail: true, fields: ["host", "slug"],
              issuer: (p) => `https://${p.host}/application/o/${p.slug}/` },
  "robo-saml": { name: "Robo Accounts (SAML)", kind: "saml", button: "Sign in with Robo Accounts", fields: ["host", "slug"],
              metadataUrl: (p) => `https://${p.host}/application/saml/${p.slug}/metadata/` },
  oidc:     { name: "OpenID Connect", kind: "oidc", button: "Sign in with OpenID Connect", scopes: "openid email profile", verifiedEmail: true, fields: ["issuer"] },
  oauth2:   { name: "OAuth 2.0", kind: "oauth2", button: "Sign in with OAuth 2.0", scopes: "", verifiedEmail: true, fields: ["authorizeUrl", "tokenUrl", "userinfoUrl"] },
  saml:     { name: "SAML 2.0", kind: "saml", button: "Sign in with SAML", fields: [] },
};

// Small marks for the sign-in buttons and the dashboard (inline SVG; the gate's CSP allows no outside images).
export const ICONS = {
  google: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1Z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23Z"/><path fill="#FBBC05" d="M5.84 14.1A6.6 6.6 0 0 1 5.5 12c0-.73.13-1.44.34-2.1V7.06H2.18A11 11 0 0 0 1 12c0 1.77.43 3.45 1.18 4.94l3.66-2.84Z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1A11 11 0 0 0 2.18 7.06l3.66 2.84C6.71 7.31 9.14 5.38 12 5.38Z"/></svg>',
  auth0: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#EB5424" d="M21.98 7.45 19.62 0H4.35L2.02 7.45c-1.35 4.31.03 9.2 3.81 12.02L12 24l6.16-4.55c3.76-2.81 5.18-7.69 3.82-12.01l-6.16 4.58 2.34 7.45L12 14.88l-6.16 4.58 2.36-7.43-6.19-4.55 7.63-.05L12 0l2.36 7.4 7.62.05Z"/></svg>',
  entra: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#F25022" d="M2 2h9.5v9.5H2z"/><path fill="#7FBA00" d="M12.5 2H22v9.5h-9.5z"/><path fill="#00A4EF" d="M2 12.5h9.5V22H2z"/><path fill="#FFB900" d="M12.5 12.5H22V22h-9.5z"/></svg>',
  okta: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="7.4" fill="none" stroke="#2d6bff" stroke-width="4.2"/></svg>',
  github: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.52-1.33-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.56-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.8 1.18 1.83 1.18 3.09 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z"/></svg>',
  robo: '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="#f0c98a" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="7" width="16" height="12" rx="3.5"/><path d="M12 3.5V7M9 12.5h.01M15 12.5h.01M9.5 16h5M2 12v3M22 12v3"/></svg>',
  oidc: '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#f78c40" d="M14.54 0 11.46 1.6v19.38c-3.88-.34-7.75-2.14-7.75-5.33 0-2.66 2.95-4.98 6.2-5.6V7.3C4.48 8.06 0 11.45 0 15.65 0 20.24 5.15 23.43 11.46 24l3.08-1.47Zm.74 7.3v2.75c1.27.25 2.4.68 3.4 1.18l-1.66.9L24 13.5l-.4-4.83-1.55.86c-1.95-1.06-4.3-1.74-6.77-2.24Z"/></svg>',
  oauth2: '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="#c9ccd1" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4.5"/><path d="m11.2 11.8 8.3-8.3M16.5 6.5l2.5 2.5M14 9l2 2"/></svg>',
  saml: '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="#c9ccd1" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4 5.5v6c0 4.9 3.4 8.8 8 10 4.6-1.2 8-5.1 8-10v-6l-8-3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>',
};
// The button's words: what the owner typed, else "Sign in with <its name>"
export const buttonOf = (p) => p.button || (PRESETS[p.preset] && p.name === PRESETS[p.preset].name ? PRESETS[p.preset].button : `Sign in with ${p.name}`);
const someone = (p) => ["emails", "domains", "subjects", "groups"].some((k) => (p.allow?.[k] || []).length);
export const iconOf = (p) => ICONS[p.preset === "robo-saml" ? "robo" : p.preset] || ICONS[p.kind] || ICONS.saml;

// ---------------------------------------------------------------- small helpers
async function fetchJson(f, url, opts = {}, what = "the provider") {
  let r;
  try { r = await f(url, { redirect: "follow", signal: AbortSignal.timeout(10000), ...opts, headers: { Accept: "application/json", "User-Agent": "aegis-burrow-sso", ...(opts.headers || {}) } }); }
  catch (e) { throw new SsoError(`Couldn't reach ${what} at ${hostOf(url)}: ${e.cause?.code || e.message}`, "failed"); }
  const text = await r.text();
  if (text.length > 1024 * 1024) throw new SsoError(`${what} answered with too much.`, "failed");
  let j = null;
  try { j = JSON.parse(text); } catch { /* not JSON */ }
  if (!r.ok) throw new SsoError(`${what} said ${r.status}${j?.error ? `: ${j.error}${j.error_description ? ` (${clean(j.error_description, 200)})` : ""}` : ""}`, "failed");
  if (!j || typeof j !== "object") throw new SsoError(`${what} at ${hostOf(url)} didn't answer with JSON.`, "failed");
  return j;
}
async function fetchText(f, url, what) {
  let r;
  try { r = await f(url, { redirect: "follow", signal: AbortSignal.timeout(10000), headers: { "User-Agent": "aegis-burrow-sso" } }); }
  catch (e) { throw new SsoError(`Couldn't reach ${what} at ${hostOf(url)}: ${e.cause?.code || e.message}`, "config"); }
  const text = await r.text();
  if (!r.ok) throw new SsoError(`${what} at ${hostOf(url)} said ${r.status}.`, "config");
  if (text.length > MAX_SAML) throw new SsoError(`${what} is too large.`, "config");
  return text;
}
const hostOf = (u) => { try { return new URL(u).host; } catch { return String(u).slice(0, 80); } };
const isLoopback = (h) => /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i.test(h);
// https only, except on this machine (a provider you run next to Aegis, and the tests)
function checkUrl(v, what) {
  const s = clean(v, 1000);
  let u;
  try { u = new URL(s); } catch { throw new SsoError(`${what}: that isn't a link.`, "config"); }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopback(u.hostname))) throw new SsoError(`${what} must start with https://`, "config");
  if (u.username || u.password) throw new SsoError(`${what}: no user name or password in the link.`, "config");
  return u.href;
}
const sameIssuer = (a, b) => String(a || "").replace(/\/+$/, "") === String(b || "").replace(/\/+$/, "");
const pick = (obj, path) => String(path || "").split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
const lines = (v, n = 200, max = 200) => (Array.isArray(v) ? v : String(v ?? "").split(/[\n,]/)).map((x) => clean(x, max)).filter(Boolean).slice(0, n);

// PEM from whatever was pasted: a PEM block, or the bare base64 of a metadata file
export function pemCert(v) {
  const body = String(v || "").replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  if (!body || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) throw new SsoError("That certificate isn't base64 or PEM.", "config");
  const pem = `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
  try { new X509Certificate(pem); } catch { throw new SsoError("That isn't an X.509 certificate.", "config"); }
  return pem;
}
export function certInfo(pem) {
  try { const c = new X509Certificate(pem); return { subject: c.subject.replace(/\n/g, ", ").slice(0, 160), notAfter: Date.parse(c.validTo), fingerprint: c.fingerprint256 }; }
  catch { return null; }
}

// ---------------------------------------------------------------- XML
export const NS = { samlp: "urn:oasis:names:tc:SAML:2.0:protocol", saml: "urn:oasis:names:tc:SAML:2.0:assertion",
                    md: "urn:oasis:names:tc:SAML:2.0:metadata", ds: "http://www.w3.org/2000/09/xmldsig#" };
export const NAMEID = { email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", any: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" };
// No DOCTYPE (entities are a way in, and SAML never needs them); a parse error is an error.
export function parseXml(xml) {
  const s = String(xml || "");
  if (/<!DOCTYPE|<!ENTITY/i.test(s)) throw new SsoError("XML with a DOCTYPE is refused.", "failed");
  const fail = (m) => { throw new SsoError(`That XML doesn't parse: ${String(m).split("\n")[0].slice(0, 160)}`, "failed"); };
  const doc = new DOMParser({ errorHandler: { warning: () => {}, error: fail, fatalError: fail } }).parseFromString(s, "text/xml");
  if (!doc?.documentElement) fail("empty");
  return doc;
}
const kids = (el, ns, name) => Array.from(el?.childNodes || []).filter((n) => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name);
const kid = (el, ns, name) => kids(el, ns, name)[0] || null;
const allOf = (el, ns, name) => Array.from(el.getElementsByTagNameNS(ns, name));
const text = (el) => (el ? String(el.textContent || "").trim() : "");

// The IdP from its metadata: entity ID, the SSO endpoint (HTTP-Redirect), signing certificates.
export function parseIdpMetadata(xml) {
  const doc = parseXml(xml);
  let ed = doc.documentElement;
  if (ed.localName === "EntitiesDescriptor") ed = allOf(ed, NS.md, "EntityDescriptor").find((e) => kid(e, NS.md, "IDPSSODescriptor")) || null;
  if (!ed || ed.localName !== "EntityDescriptor" || ed.namespaceURI !== NS.md) throw new SsoError("That isn't SAML metadata (no EntityDescriptor).", "config");
  const idp = kid(ed, NS.md, "IDPSSODescriptor");
  if (!idp) throw new SsoError("That metadata has no IdP in it (IDPSSODescriptor): is it the SP's own?", "config");
  const sso = kids(idp, NS.md, "SingleSignOnService");
  const by = (b) => sso.find((s) => s.getAttribute("Binding") === `urn:oasis:names:tc:SAML:2.0:bindings:${b}`)?.getAttribute("Location") || null;
  const certs = kids(idp, NS.md, "KeyDescriptor").filter((k) => !k.getAttribute("use") || k.getAttribute("use") === "signing")
    .flatMap((k) => allOf(k, NS.ds, "X509Certificate").map((c) => pemCert(text(c))));
  const out = { entityId: ed.getAttribute("entityID") || "", ssoUrl: by("HTTP-Redirect"), postUrl: by("HTTP-POST"), certs: [...new Set(certs)] };
  if (!out.entityId) throw new SsoError("That metadata has no entityID.", "config");
  if (!out.certs.length) throw new SsoError("That metadata has no signing certificate.", "config");
  return out;
}

// Signature algorithms a SAML answer may use. HMAC never (key confusion);
// sha1 only for a provider that allows it. ECDSA and rsa-sha384 aren't in
// xml-crypto itself: node:crypto verifies them (XML DSig ECDSA is r||s).
const SIG = {
  rsa1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1", rsa256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  rsa384: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", rsa512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  pss256: "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
  ec1: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", ec256: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  ec384: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", ec512: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
};
const DIG = { sha1: "http://www.w3.org/2000/09/xmldsig#sha1", sha256: "http://www.w3.org/2001/04/xmlenc#sha256",
              sha384: "http://www.w3.org/2001/04/xmldsig-more#sha384", sha512: "http://www.w3.org/2001/04/xmlenc#sha512" };
const nodeSig = (uri, hash, ec) => class {
  getAlgorithmName() { return uri; }
  getSignature(material, key) { return csign(hash, Buffer.from(material), ec ? { key, dsaEncoding: "ieee-p1363" } : key).toString("base64"); }
  verifySignature(material, key, value) {
    try { return cverify(hash, Buffer.from(material), ec ? { key, dsaEncoding: "ieee-p1363" } : key, Buffer.from(value, "base64")); } catch { return false; }
  }
};
const nodeHash = (uri, hash) => class { getAlgorithmName() { return uri; } getHash(xml) { return createHash(hash).update(xml, "utf8").digest("base64"); } };
const BUILTIN = new SignedXml();
export function samlAlgorithms(allowSha1 = false) {
  const sigs = { [SIG.rsa256]: BUILTIN.SignatureAlgorithms[SIG.rsa256], [SIG.rsa512]: BUILTIN.SignatureAlgorithms[SIG.rsa512],
                 [SIG.pss256]: BUILTIN.SignatureAlgorithms[SIG.pss256], [SIG.rsa384]: nodeSig(SIG.rsa384, "sha384"),
                 [SIG.ec256]: nodeSig(SIG.ec256, "sha256", true), [SIG.ec384]: nodeSig(SIG.ec384, "sha384", true), [SIG.ec512]: nodeSig(SIG.ec512, "sha512", true) };
  const digs = { [DIG.sha256]: BUILTIN.HashAlgorithms[DIG.sha256], [DIG.sha512]: BUILTIN.HashAlgorithms[DIG.sha512], [DIG.sha384]: nodeHash(DIG.sha384, "sha384") };
  if (allowSha1) { sigs[SIG.rsa1] = BUILTIN.SignatureAlgorithms[SIG.rsa1]; sigs[SIG.ec1] = nodeSig(SIG.ec1, "sha1", true); digs[DIG.sha1] = BUILTIN.HashAlgorithms[DIG.sha1]; }
  return { sigs, digs };
}
export const SAML_SIG = SIG, SAML_DIGEST = DIG;

// One ds:Signature, a direct child of `parent`, with exactly one reference, to
// `parent` itself: the canonical XML it covers if one of `certs` signed it, else null.
function signedBy(xml, sigNode, parent, certs, allowSha1) {
  const id = parent.getAttribute("ID");
  if (!id) return null;
  const { sigs, digs } = samlAlgorithms(allowSha1);
  for (const cert of certs) {
    const sx = new SignedXml({ publicCert: cert, getCertFromKeyInfo: () => null });      // never a key the message brings itself
    sx.SignatureAlgorithms = sigs; sx.HashAlgorithms = digs;
    try {
      sx.loadSignature(sigNode);
      const refs = sx.getReferences();
      if (refs.length !== 1 || refs[0].uri !== `#${id}`) return null;
      if (sx.checkSignature(xml) !== true) continue;
      const signed = sx.getSignedReferences();
      if (signed.length === 1) return signed[0];
    } catch { /* not this certificate, or not a signature we take */ }
  }
  return null;
}
const instant = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? t : NaN; };

// A SAMLResponse (the XML, decoded): verified, checked, and what it says about
// who signed in. Throws SsoError for anything off.
//   idp: { entityId, certs }   sp: { acs, entityId }   allowSha1, now (ms), skew (s)
export function verifySamlResponse(xml, { idp, sp, allowSha1 = false, now = Date.now(), skew = SKEW_S }) {
  const doc = parseXml(xml);
  const res = doc.documentElement;
  if (res.namespaceURI !== NS.samlp || res.localName !== "Response") throw new SsoError("That isn't a SAML Response.");
  if (allOf(doc, NS.saml, "EncryptedAssertion").length) throw new SsoError("The assertion is encrypted: switch assertion encryption off at the IdP (the signature protects it here).", "config");
  // exactly one assertion in the whole document, straight under the Response: no room to wrap a signature
  const every = allOf(doc, NS.saml, "Assertion"), direct = kids(res, NS.saml, "Assertion");
  if (every.length !== 1 || direct.length !== 1) throw new SsoError(every.length ? "The response holds more than one assertion (refused: signature wrapping)." : "The response holds no assertion.");
  const asr = direct[0];
  // the signature: on the Response, on the Assertion, or both (one valid one is enough)
  let signedRes = null, signedAsr = null;
  const rSig = kids(res, NS.ds, "Signature"), aSig = kids(asr, NS.ds, "Signature");
  if (rSig.length > 1 || aSig.length > 1) throw new SsoError("More than one signature in one place.");
  if (rSig[0]) {
    const c = signedBy(xml, rSig[0], res, idp.certs, allowSha1);
    if (c) {
      const sdoc = parseXml(c), sres = sdoc.documentElement;
      const sa = kids(sres, NS.saml, "Assertion");
      if (sres.localName !== "Response" || sres.getAttribute("ID") !== res.getAttribute("ID") || sa.length !== 1 || allOf(sdoc, NS.saml, "Assertion").length !== 1) throw new SsoError("The signed response isn't the one that was sent.");
      signedRes = sres; signedAsr = sa[0];
    }
  }
  if (!signedAsr && aSig[0]) {
    const c = signedBy(xml, aSig[0], asr, idp.certs, allowSha1);
    if (c) {
      const sa = parseXml(c).documentElement;
      if (sa.localName !== "Assertion" || sa.namespaceURI !== NS.saml || sa.getAttribute("ID") !== asr.getAttribute("ID")) throw new SsoError("The signed assertion isn't the one that was sent.");
      signedAsr = sa;
    }
  }
  if (!signedAsr) {
    throw new SsoError(rSig[0] || aSig[0] ? "The signature doesn't verify with the IdP's certificate (or uses an algorithm not allowed here, like sha1)."
                                         : "Neither the response nor the assertion is signed.");
  }
  // from here on: only the signed XML (the response's own fields from the signed copy when there is one)
  const R = signedRes || res, A = signedAsr;
  const lo = now - skew * 1000, hi = now + skew * 1000;
  const status = kid(kid(R, NS.samlp, "Status"), NS.samlp, "StatusCode");
  const sv = status?.getAttribute("Value") || "";
  if (!sv.endsWith(":Success")) {
    const sub = kid(status, NS.samlp, "StatusCode")?.getAttribute("Value") || "";
    throw new SsoError(`The IdP said no: ${(sub || sv || "no status").split(":").pop()}${text(kid(kid(R, NS.samlp, "Status"), NS.samlp, "StatusMessage")) ? ` (${clean(text(kid(kid(R, NS.samlp, "Status"), NS.samlp, "StatusMessage")), 160)})` : ""}`);
  }
  const dest = R.getAttribute("Destination");
  if (dest && dest !== sp.acs) throw new SsoError(`The response is for ${clean(dest, 120)}, not this ACS URL (${sp.acs}).`);
  const rIss = text(kid(R, NS.saml, "Issuer")), aIss = text(kid(A, NS.saml, "Issuer"));
  if (aIss !== idp.entityId || (rIss && rIss !== idp.entityId)) throw new SsoError(`The issuer is ${clean(aIss || rIss, 120) || "missing"}, not the IdP's entity ID (${idp.entityId}).`);
  // the subject, and its bearer confirmation: Recipient = our ACS, still in time, and which request it answers
  const subject = kid(A, NS.saml, "Subject");
  const nameIdEl = kid(subject, NS.saml, "NameID");
  if (!nameIdEl || !text(nameIdEl)) throw new SsoError("The assertion has no NameID.");
  const scd = kids(subject, NS.saml, "SubjectConfirmation").filter((s) => s.getAttribute("Method") === "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    .map((s) => kid(s, NS.saml, "SubjectConfirmationData")).filter(Boolean);
  const good = scd.filter((d) => d.getAttribute("Recipient") === sp.acs);
  if (!good.length) throw new SsoError(scd.length ? `The assertion's Recipient isn't this ACS URL (${sp.acs}).` : "The assertion has no bearer subject confirmation.");
  const conf = good.find((d) => instant(d.getAttribute("NotOnOrAfter")) > lo && !(instant(d.getAttribute("NotBefore")) > hi));
  if (!conf) throw new SsoError("The assertion has expired (check this machine's clock, and the IdP's).", "expired");
  const inResponseTo = conf.getAttribute("InResponseTo") || R.getAttribute("InResponseTo") || null;
  const rIrt = R.getAttribute("InResponseTo");
  if (rIrt && conf.getAttribute("InResponseTo") && rIrt !== conf.getAttribute("InResponseTo")) throw new SsoError("The response and the assertion answer different requests.");
  // conditions: the time window and the audience
  const cond = kid(A, NS.saml, "Conditions");
  if (cond) {
    const nb = instant(cond.getAttribute("NotBefore")), na = instant(cond.getAttribute("NotOnOrAfter"));
    if (cond.getAttribute("NotBefore") && !(nb <= hi)) throw new SsoError("The assertion isn't valid yet (check this machine's clock, and the IdP's).", "expired");
    if (cond.getAttribute("NotOnOrAfter") && !(na > lo)) throw new SsoError("The assertion has expired (check this machine's clock, and the IdP's).", "expired");
  }
  const ar = cond ? kids(cond, NS.saml, "AudienceRestriction") : [];
  if (!ar.length) throw new SsoError("The assertion names no audience.");
  for (const r of ar) {
    if (!kids(r, NS.saml, "Audience").some((a) => text(a) === sp.entityId)) throw new SsoError(`The assertion is for another audience (${clean(kids(r, NS.saml, "Audience").map(text).join(", "), 160)}), not this SP's entity ID (${sp.entityId}).`);
  }
  // what it says
  const attrs = {};
  for (const st of kids(A, NS.saml, "AttributeStatement")) {
    for (const at of kids(st, NS.saml, "Attribute")) {
      const name = at.getAttribute("Name");
      if (!name) continue;
      const vals = kids(at, NS.saml, "AttributeValue").map(text).filter(Boolean).slice(0, 200);
      attrs[name] = [...(attrs[name] || []), ...vals];
      const friendly = at.getAttribute("FriendlyName");
      if (friendly && !attrs[friendly]) attrs[friendly] = attrs[name];
    }
  }
  return { id: A.getAttribute("ID"), issuer: aIss, inResponseTo, nameId: text(nameIdEl), nameIdFormat: nameIdEl.getAttribute("Format") || "",
           attrs, until: Math.max(instant(conf.getAttribute("NotOnOrAfter")) || 0, instant(cond?.getAttribute("NotOnOrAfter")) || 0) || now + 600e3 };
}

// Who a SAML assertion names, from the attributes most IdPs send (authentik's, Entra's, Okta's, the OIDs).
const SAML_ATTR = {
  email: ["email", "mail", "emailAddress", "Email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"],
  name: ["name", "displayName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "http://schemas.microsoft.com/identity/claims/displayname", "urn:oid:2.16.840.1.113730.3.1.241", "cn"],
  username: ["username", "http://goauthentik.io/2021/02/saml/username", "uid", "urn:oid:0.9.2342.19200300.100.1.1", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"],
  groups: ["groups", "http://schemas.xmlsoap.org/claims/Group", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "memberOf", "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"],
};
export function samlIdentity(r, p = {}) {
  const first = (k) => { for (const n of [...(p.attrs?.[k] ? [p.attrs[k]] : []), ...SAML_ATTR[k]]) if (r.attrs[n]?.length) return r.attrs[n]; return []; };
  const email = first("email")[0] || (r.nameIdFormat === NAMEID.email || /^[^@\s]+@[^@\s]+$/.test(r.nameId) ? r.nameId : "");
  return { sub: r.nameId, email: email.toLowerCase(), emailVerified: true, name: first("name")[0] || "", username: first("username")[0] || "",
           groups: [...new Set(first("groups"))].slice(0, 200) };
}

// ---------------------------------------------------------------- id_tokens
const ALGS = { RS256: { hash: "sha256", kty: "RSA" }, RS384: { hash: "sha384", kty: "RSA" }, RS512: { hash: "sha512", kty: "RSA" },
               PS256: { hash: "sha256", kty: "RSA", pss: true }, ES256: { hash: "sha256", kty: "EC", crv: "P-256" },
               ES384: { hash: "sha384", kty: "EC", crv: "P-384" }, EdDSA: { hash: null, kty: "OKP" } };
export const JWT_ALGS = Object.keys(ALGS);
const jwkPublic = (k) => (k.kty === "RSA" ? { kty: "RSA", n: k.n, e: k.e } : k.kty === "EC" ? { kty: "EC", crv: k.crv, x: k.x, y: k.y } : { kty: "OKP", crv: k.crv, x: k.x });
function decodeJwt(jwt) {
  const parts = String(jwt || "").split(".");
  if (parts.length !== 3) throw new SsoError("The id_token isn't a JWT.");
  try { return { header: JSON.parse(Buffer.from(parts[0], "base64url")), claims: JSON.parse(Buffer.from(parts[1], "base64url")), data: Buffer.from(`${parts[0]}.${parts[1]}`), sig: Buffer.from(parts[2], "base64url") }; }
  catch { throw new SsoError("The id_token doesn't decode."); }
}
// Is the signature by one of these keys (a JWKS's keys)?
export function jwtSignedBy(jwt, keys) {
  const t = decodeJwt(jwt), spec = ALGS[t.header.alg];
  if (!spec) throw new SsoError(`The id_token is signed with ${clean(t.header.alg, 20) || "nothing"}, which isn't taken here.`);
  const cands = (keys || []).filter((k) => k && k.kty === spec.kty && (!t.header.kid || k.kid === t.header.kid) && (!k.use || k.use === "sig")
                                       && (!k.alg || k.alg === t.header.alg) && (!spec.crv || k.crv === spec.crv));
  return { t, cands, ok: cands.some((k) => {
    try {
      const key = createPublicKey({ key: jwkPublic(k), format: "jwk" });
      const opt = spec.pss ? { key, padding: C.RSA_PKCS1_PSS_PADDING, saltLength: C.RSA_PSS_SALTLEN_DIGEST } : spec.kty === "EC" ? { key, dsaEncoding: "ieee-p1363" } : key;
      return cverify(spec.hash, t.data, opt, t.sig);
    } catch { return false; }
  }) };
}
// The claims, once iss, aud/azp, the times and the nonce are right.
export function checkIdClaims(c, { issuers, clientId, nonce, now = Date.now(), skew = SKEW_S }) {
  const s = Math.floor(now / 1000);
  if (!issuers.some((i) => i === c.iss || (i.includes("{tenantid}") && c.tid && i.replace("{tenantid}", c.tid) === c.iss))) throw new SsoError(`The id_token's issuer (${clean(c.iss, 120)}) isn't the provider's (${issuers[0]}).`);
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(clientId)) throw new SsoError("The id_token is for another client (aud).");
  if ((aud.length > 1 || c.azp !== undefined) && c.azp !== clientId) throw new SsoError("The id_token was issued to another client (azp).");
  if (typeof c.exp !== "number" || c.exp <= s - skew) throw new SsoError("The id_token has expired (check this machine's clock).", "expired");
  if (typeof c.iat !== "number" || c.iat > s + skew) throw new SsoError("The id_token was issued in the future (check this machine's clock).", "expired");
  if (typeof c.nbf === "number" && c.nbf > s + skew) throw new SsoError("The id_token isn't valid yet (check this machine's clock).", "expired");
  if (!nonce || c.nonce !== nonce) throw new SsoError("The id_token's nonce doesn't match this sign-in.");
  if (!c.sub) throw new SsoError("The id_token has no subject.");
  return c;
}

// Who the claims (an id_token's, userinfo's) say signed in.
export function claimsIdentity(c, p = {}) {
  const m = p.claims || {};
  const val = (path, ...fallbacks) => { for (const q of [path, ...fallbacks]) { const v = q ? pick(c, q) : undefined; if (v !== undefined && v !== null && v !== "") return v; } return undefined; };
  const groups = val(m.groups, "groups", "roles");
  const ev = val(m.emailVerified, "email_verified");
  return { sub: String(val(m.sub, "sub", "id") ?? ""), email: String(val(m.email, "email") ?? "").toLowerCase(),
           emailVerified: ev === true || ev === "true", name: String(val(m.name, "name") ?? ""),
           username: String(val(m.username, "preferred_username", "login", "upn", "nickname") ?? ""),
           groups: (Array.isArray(groups) ? groups : groups ? String(groups).split(/[\s,]+/) : []).map((g) => clean(g, 200)).filter(Boolean).slice(0, 200) };
}

// Is this identity on the provider's allow list? Nobody is, until the owner adds someone.
export function allowed(p, id) {
  const a = p.allow || {}, low = (xs) => (xs || []).map((x) => String(x).toLowerCase());
  const email = String(id.email || "").toLowerCase(), trusted = !!email && (id.emailVerified || p.verifiedEmail === false);
  if (id.sub && (a.subjects || []).includes(id.sub)) return { ok: true, by: "subject" };
  if (trusted && low(a.emails).includes(email)) return { ok: true, by: "email" };
  if (trusted && low(a.domains).includes(email.split("@")[1])) return { ok: true, by: "domain" };
  if ((id.groups || []).some((g) => (a.groups || []).includes(g))) return { ok: true, by: "group" };
  const none = !["emails", "domains", "subjects", "groups"].some((k) => (a[k] || []).length);
  return { ok: false, why: none ? "nobody is allowed yet (add someone to this provider's allow list)"
    : email && !trusted && (low(a.emails).includes(email) || low(a.domains).includes(email.split("@")[1])) ? "the provider didn't say this email is verified" : "not on the allow list" };
}
export const identityLabel = (id) => id.email || id.username || id.sub;

// ---------------------------------------------------------------- the store and the flows
export class Sso {
  // settings: aegis/config.mjs Settings; box: { seal(text), open(sealed) } for secrets; fetch: for the tests
  constructor({ settings, log = () => {}, box, fetch: f = globalThis.fetch, skew = SKEW_S, jwksMinMs = 30000, now = () => Date.now() }) {
    Object.assign(this, { settings, log, box, f, skew, jwksMinMs, now });
    this.flows = new Map();           // state -> a sign-in on its way (provider, PKCE verifier, nonce, next, test, browser)
    this.tests = new Map();           // token -> a test sign-in from the dashboard, and what came back
    this.disco = new Map();           // issuer -> { doc, at }
    this.jwks = new Map();            // jwks_uri -> { keys, at }
    this.seen = new Map();            // a SAML assertion ID -> until when (no replays)
  }

  // ---- settings
  conf() { const s = this.settings.get("sso") || {}; return { base: s.base || null, only: !!s.only, providers: Array.isArray(s.providers) ? s.providers : [] }; }
  write(patch) { this.settings.set({ sso: { ...this.conf(), ...patch } }); }
  list() { return this.conf().providers; }
  get(id) { return this.list().find((p) => p.id === id) || null; }
  enabled() { return this.list().filter((p) => p.enabled); }
  // on the sign-in page: switched on, and someone may use it (a button that lets nobody in is no button)
  shown() { return this.list().filter((p) => p.enabled && someone(p)); }
  setOptions({ base, only } = {}) {
    const patch = {};
    if (base !== undefined) {
      if (!base) patch.base = null;
      else {
        const u = new URL(checkUrl(base, "The sign-in address"));
        if (u.pathname !== "/" || u.search || u.hash) throw new SsoError("The sign-in address is just https://name (no path).", "config");
        patch.base = u.origin;
      }
    }
    if (only !== undefined) patch.only = !!only;
    this.write(patch);
  }

  // what the dashboard sees: no secrets
  view(p, base) {
    const pr = PRESETS[p.preset] || PRESETS[p.kind];
    return { ...Object.fromEntries(Object.entries(p).filter(([k]) => k !== "secret" && k !== "metadataXml")), buttonSet: p.button || "", hasSecret: !!p.secret, hasMetadataXml: !!p.metadataXml,
             button: buttonOf(p), issuerResolved: p.kind === "oidc" ? this.issuerOf(p) : null,
             certs: (p.idp?.certs || []).map(certInfo).filter(Boolean), urls: base ? this.urls(p, base) : null,
             nobody: !someone(p) };
  }
  urls(p, base) {
    const at = `${base}/__gate/sso/${p.id}`;
    return p.kind === "saml" ? { acs: `${at}/acs`, entityId: `${at}/metadata`, metadata: `${at}/metadata`, start: `${at}/start`, login: `${base}/__gate/login` }
      : { redirect: `${at}/callback`, start: `${at}/start`, logout: `${base}/__gate/login`, origin: base, login: `${base}/__gate/login` };
  }
  issuerOf(p) { const pr = PRESETS[p.preset]; return pr?.issuer ? pr.issuer(p) : p.issuer; }

  // A provider from the dashboard's form: new (no prev) or changed. Checked
  // against the provider itself (discovery, metadata) before it is kept.
  async clean(input, prev = null) {
    const b = input || {};
    const preset = prev?.preset || clean(b.preset, 20);
    const pr = PRESETS[preset];
    if (!pr) throw new SsoError("Pick a kind of provider.", "config");
    const p = { ...(prev || {}), preset, kind: pr.kind };
    if (!prev) {
      const taken = new Set(this.list().map((x) => x.id));
      const want = clean(b.id || preset, 32).toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "") || "sso";
      let id = want, n = 2;
      while (taken.has(id) || id === "callback" || !ID_RE.test(id)) id = `${want.slice(0, 28)}-${n++}`;
      p.id = id; p.created = this.now(); p.enabled = b.enabled !== false;
    }
    const has = (k) => b[k] !== undefined;
    if (has("name") || !prev) p.name = clean(b.name, 60) || pr.name;
    if (has("button")) p.button = clean(b.button, 60) || null;
    if (has("enabled")) p.enabled = !!b.enabled;
    const need = (k, label, fix = (v) => v) => {
      if (has(k)) p[k] = fix(b[k]);
      if (!p[k]) throw new SsoError(`${label} is missing.`, "config");
    };
    for (const f of pr.fields || []) {
      if (f === "domain") need("domain", pr.preset === "okta" ? "The Okta domain" : "The domain", (v) => { const h = LOOSE_HOST(v); if (!HOST_RE.test(h)) throw new SsoError("The domain looks like tenant.us.auth0.com: no https://, no path.", "config"); return h; });
      else if (f === "tenant") need("tenant", "The tenant ID", (v) => { const t = clean(v, 100).toLowerCase(); if (!/^[a-z0-9.-]{2,100}$/.test(t)) throw new SsoError("The tenant is a directory (tenant) ID, a domain like contoso.onmicrosoft.com, or organizations / common.", "config"); return t; });
      else if (f === "authServer") { if (has("authServer")) { const a = clean(b.authServer, 60); if (a && !/^[A-Za-z0-9_-]+$/.test(a)) throw new SsoError("The authorization server is its ID, like default.", "config"); p.authServer = a; } }
      else if (f === "host") need("host", "The Robo Accounts address", (v) => { const h = LOOSE_HOST(v).replace(/\/.*$/, ""); if (!HOST_RE.test(h)) throw new SsoError("The address is a name like accounts.example.com: no https://, no path.", "config"); return h; });
      else if (f === "slug") need("slug", "The application slug", (v) => { const s = clean(v, 80).toLowerCase(); if (!/^[a-z0-9][a-z0-9_-]*$/.test(s)) throw new SsoError("The slug is the application's slug, like aegis.", "config"); return s; });
      else need(f, { issuer: "The issuer", authorizeUrl: "The authorization URL", tokenUrl: "The token URL", userinfoUrl: "The userinfo URL" }[f], (v) => checkUrl(v, { issuer: "The issuer", authorizeUrl: "The authorization URL", tokenUrl: "The token URL", userinfoUrl: "The userinfo URL" }[f]));
    }
    if (p.kind === "oidc" || p.kind === "oauth2") {
      need("clientId", "The client ID", (v) => clean(v, 300));
      if (typeof b.clientSecret === "string" && b.clientSecret.trim()) p.secret = this.box.seal(b.clientSecret.trim());
      if (b.clearSecret) delete p.secret;
      if (has("scopes") || !prev) p.scopes = clean(b.scopes ?? pr.scopes, 300).split(/\s+/).filter(Boolean).join(" ") || pr.scopes;
      if (p.kind === "oidc" && !p.scopes.split(" ").includes("openid")) p.scopes = `openid ${p.scopes}`;
      if (has("tokenAuth") || !prev) { const t = clean(b.tokenAuth || "auto", 10); p.tokenAuth = ["auto", "basic", "post", "none"].includes(t) ? t : "auto"; }
      if (has("verifiedEmail") || !prev) p.verifiedEmail = b.verifiedEmail === undefined ? pr.verifiedEmail !== false : !!b.verifiedEmail;
      if (has("connection") || !prev) p.connection = preset === "auth0" ? clean(b.connection, 60).replace(/[^A-Za-z0-9_-]/g, "") : "";
      if (has("claims")) p.claims = Object.fromEntries(["sub", "email", "emailVerified", "name", "username", "groups"].map((k) => [k, clean(b.claims?.[k], 80)]).filter(([, v]) => v));
      if (p.kind === "oauth2" && pr.authorizeUrl) Object.assign(p, { authorizeUrl: pr.authorizeUrl, tokenUrl: pr.tokenUrl, userinfoUrl: pr.userinfoUrl, emailsUrl: pr.emailsUrl });
      if (p.tokenAuth !== "none" && !p.secret) throw new SsoError("The client secret is missing.", "config");
      if (p.kind === "oidc") {
        p.issuer = this.issuerOf(p);
        checkUrl(p.issuer, "The issuer");
        this.disco.delete(p.issuer);
        await this.discover(p);                                  // the provider answers, before it's kept
      }
    } else {
      if (has("allowSha1")) p.allowSha1 = !!b.allowSha1;
      if (has("idpInitiated")) p.idpInitiated = !!b.idpInitiated;
      if (has("nameIdFormat") || !prev) p.nameIdFormat = b.nameIdFormat === "any" ? "any" : "email";
      if (has("attrs")) p.attrs = Object.fromEntries(["email", "name", "username", "groups"].map((k) => [k, clean(b.attrs?.[k], 200)]).filter(([, v]) => v));
      const source = pr.metadataUrl ? "url" : clean(b.source || prev?.source || "url", 10);
      p.source = ["url", "xml", "manual"].includes(source) ? source : "url";
      if (pr.metadataUrl) p.metadataUrl = pr.metadataUrl(p);
      if (p.source === "url") need("metadataUrl", "The IdP metadata URL", (v) => checkUrl(v, "The IdP metadata URL"));
      if (p.source === "xml") { if (typeof b.metadataXml === "string" && b.metadataXml.trim()) p.metadataXml = b.metadataXml.trim().slice(0, MAX_SAML); if (!p.metadataXml) throw new SsoError("Paste the IdP's metadata XML.", "config"); }
      if (p.source === "manual") {
        need("idpEntityId", "The IdP entity ID (issuer)", (v) => clean(v, 500));
        need("idpSsoUrl", "The IdP SSO URL", (v) => checkUrl(v, "The IdP SSO URL"));
        if (typeof b.idpCert === "string" && b.idpCert.trim()) p.idpCert = pemCert(b.idpCert);
        if (!p.idpCert) throw new SsoError("Paste the IdP's signing certificate.", "config");
      }
      p.idp = await this.idpOf(p, true);
    }
    if (has("allow") || !prev) {
      const a = b.allow || {};
      p.allow = { emails: lines(a.emails).map((x) => x.toLowerCase()), domains: lines(a.domains).map((x) => x.toLowerCase().replace(/^@/, "")),
                  subjects: lines(a.subjects, 200, 500), groups: lines(a.groups) };
    }
    p.updated = this.now();
    return p;
  }
  async add(input) {
    if (this.list().length >= 20) throw new SsoError("That's 20 providers already.", "config");
    const p = await this.clean(input);
    this.write({ providers: [...this.list(), p] });
    return p;
  }
  async update(id, input) {
    const prev = this.get(id);
    if (!prev) throw new SsoError("No such provider.", "config");
    const p = await this.clean(input, prev);
    this.write({ providers: this.list().map((x) => (x.id === id ? p : x)) });
    return p;
  }
  // a quick switch (on/off) or an allow-list entry, without asking the provider again
  patch(id, fn) {
    const prev = this.get(id);
    if (!prev) throw new SsoError("No such provider.", "config");
    const p = { ...prev, allow: { emails: [], domains: [], subjects: [], groups: [], ...(prev.allow || {}) } };
    fn(p);
    p.updated = this.now();
    this.write({ providers: this.list().map((x) => (x.id === id ? p : x)) });
    return p;
  }
  allow(id, kind, value) {
    const k = { email: "emails", domain: "domains", subject: "subjects", group: "groups" }[kind];
    if (!k) throw new SsoError("Allow an email, a domain, a subject or a group.", "config");
    let v = clean(value, 500);
    if (k === "emails" || k === "domains") v = v.toLowerCase().replace(/^@/, "");
    if (!v) throw new SsoError("Nothing to allow.", "config");
    return this.patch(id, (p) => { if (!p.allow[k].includes(v)) p.allow[k] = [...p.allow[k], v]; });
  }
  remove(id) {
    if (!this.get(id)) throw new SsoError("No such provider.", "config");
    const providers = this.list().filter((x) => x.id !== id);
    this.write({ providers, ...(providers.some((x) => x.enabled && someone(x)) ? {} : { only: false }) });     // never SSO-only with nothing to sign in with
  }

  // ---- OIDC discovery and keys
  async discover(p) {
    const iss = this.issuerOf(p), hit = this.disco.get(iss);
    if (hit && this.now() - hit.at < META_TTL_MS) return hit.doc;
    const url = `${iss.replace(/\/+$/, "")}/.well-known/openid-configuration`;
    const doc = await fetchJson(this.f, url, {}, "The provider's discovery document");
    // (Entra's multi-tenant endpoints, common and organizations, publish a template: …/{tenantid}/v2.0)
    if (!sameIssuer(doc.issuer, iss) && !(p.preset === "entra" && String(doc.issuer).includes("{tenantid}"))) throw new SsoError(`The discovery document is for issuer ${clean(doc.issuer, 120)}, not ${iss}.`, "config");
    for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
      if (!doc[k]) throw new SsoError(`The discovery document has no ${k}.`, "config");
      checkUrl(doc[k], k);
    }
    this.disco.set(iss, { doc, at: this.now() });
    return doc;
  }
  async keys(uri, kid) {
    const hit = this.jwks.get(uri), now = this.now();
    const stale = !hit || now - hit.at > META_TTL_MS || (kid && !hit.keys.some((k) => k.kid === kid) && now - hit.at >= this.jwksMinMs);
    if (!stale) return hit.keys;
    const j = await fetchJson(this.f, uri, {}, "The provider's keys (JWKS)");
    const keys = Array.isArray(j.keys) ? j.keys.filter((k) => k && typeof k === "object") : [];
    this.jwks.set(uri, { keys, at: now });
    return keys;
  }
  async verifyIdToken(p, doc, jwt, nonce) {
    const { header } = decodeJwt(jwt);
    const r = jwtSignedBy(jwt, await this.keys(doc.jwks_uri, header.kid));       // (a kid it doesn't know: the JWKS again, keys rotate)
    if (!r.ok) throw new SsoError(r.cands.length ? "The id_token's signature doesn't verify." : "The id_token is signed with a key the provider doesn't publish.");
    const issuers = [doc.issuer, ...(PRESETS[p.preset]?.aliases || [])];
    return checkIdClaims(r.t.claims, { issuers, clientId: p.clientId, nonce, now: this.now(), skew: this.skew });
  }

  // ---- SAML: the IdP (from its metadata URL, pasted XML, or by hand)
  async idpOf(p, fresh = false) {
    if (p.source === "manual") return { entityId: p.idpEntityId, ssoUrl: p.idpSsoUrl, certs: [p.idpCert], at: this.now() };
    if (p.source === "xml") return { ...parseIdpMetadata(p.metadataXml), at: this.now() };
    if (!fresh && p.idp && this.now() - (p.idp.at || 0) < SAML_META_TTL_MS) return p.idp;
    try {
      const idp = { ...parseIdpMetadata(await fetchText(this.f, p.metadataUrl, "The IdP metadata")), at: this.now() };
      if (!fresh && p.id && this.get(p.id)) this.patch(p.id, (x) => { x.idp = idp; });          // certificates roll over: keep the newest
      return idp;
    } catch (e) {
      if (!fresh && p.idp) { this.log("sso:", p.id, "couldn't refresh the IdP metadata, using the last copy:", e.message); return p.idp; }
      throw e;
    }
  }
  metadata(p, base) {
    const u = this.urls(p, base);
    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="${NS.md}" entityID="${xmlEsc(u.entityId)}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="${NS.samlp}">
    <md:NameIDFormat>${p.nameIdFormat === "any" ? NAMEID.any : NAMEID.email}</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${xmlEsc(u.acs)}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`;
  }

  // ---- the flows
  sweep() {
    const now = this.now();
    for (const [k, f] of this.flows) if (f.exp < now) this.flows.delete(k);
    for (const [k, t] of this.tests) if (t.exp < now) this.tests.delete(k);
    for (const [k, until] of this.seen) if (until < now) this.seen.delete(k);
    if (this.flows.size > 2000) for (const k of [...this.flows.keys()].slice(0, 1000)) this.flows.delete(k);     // the oldest half
  }
  // Where the browser goes to sign in. bind: the browser's own random value (a cookie the gate sets).
  async start(p, { base, next = "/", test = null, bind }) {
    this.sweep();
    const state = b64u(randomBytes(24));
    const flow = { pid: p.id, kind: p.kind, next, test, bind: bind ? b64u(sha256(bind)) : null, exp: this.now() + FLOW_TTL_MS };
    const u = this.urls(p, base);
    if (p.kind === "saml") {
      const idp = await this.idpOf(p);
      if (!idp.ssoUrl) throw new SsoError("The IdP has no HTTP-Redirect sign-in endpoint (SingleSignOnService): only that binding is supported.", "config");
      flow.reqId = `_${randomBytes(20).toString("hex")}`;
      const req = `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${flow.reqId}" Version="2.0" IssueInstant="${new Date(this.now()).toISOString()}" `
        + `Destination="${xmlEsc(idp.ssoUrl)}" AssertionConsumerServiceURL="${xmlEsc(u.acs)}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`
        + `<saml:Issuer>${xmlEsc(u.entityId)}</saml:Issuer><samlp:NameIDPolicy Format="${p.nameIdFormat === "any" ? NAMEID.any : NAMEID.email}" AllowCreate="true"/></samlp:AuthnRequest>`;
      this.flows.set(state, flow);
      const q = new URLSearchParams({ SAMLRequest: deflateRawSync(Buffer.from(req)).toString("base64"), RelayState: state });
      return `${idp.ssoUrl}${idp.ssoUrl.includes("?") ? "&" : "?"}${q}`;
    }
    const doc = p.kind === "oidc" ? await this.discover(p) : null;
    flow.verifier = b64u(randomBytes(32));
    if (p.kind === "oidc") flow.nonce = b64u(randomBytes(24));
    const q = new URLSearchParams({ response_type: "code", client_id: p.clientId, redirect_uri: u.redirect, scope: p.scopes || "", state,
                                    code_challenge: b64u(sha256(flow.verifier)), code_challenge_method: "S256" });
    if (!p.scopes) q.delete("scope");
    if (flow.nonce) q.set("nonce", flow.nonce);
    for (const [k, v] of Object.entries(PRESETS[p.preset]?.params || {})) q.set(k, v);
    if (p.connection) q.set("connection", p.connection);           // Auth0: straight to one connection (google-oauth2)
    this.flows.set(state, flow);
    const at = doc ? doc.authorization_endpoint : p.authorizeUrl;
    return `${at}${at.includes("?") ? "&" : "?"}${q}`;
  }
  take(state, p, bind, { loose = false } = {}) {
    this.sweep();
    const flow = typeof state === "string" ? this.flows.get(state) : null;
    if (!flow || flow.pid !== p.id) throw new SsoError("This sign-in expired or was already used. Start again.", "expired");
    this.flows.delete(state);
    // the browser that started it (a SAML answer can come without the cookie over plain HTTP)
    if (bind ? flow.bind !== b64u(sha256(bind)) : !(loose && flow.kind === "saml")) throw new SsoError("This sign-in was started in another browser. Start again.", "expired", flow);
    return flow;
  }
  // OIDC / OAuth 2.0: back from the provider with ?code&state (or ?error)
  async callback(p, { base, query, bind }) {
    const flow = this.take(query.get("state"), p, bind);
    try {
      if (query.get("error")) {
        const e = query.get("error");
        throw new SsoError(`The provider said ${clean(e, 60)}${query.get("error_description") ? `: ${clean(query.get("error_description"), 200)}` : ""}`, e === "access_denied" ? "cancelled" : "failed");
      }
      const code = query.get("code");
      if (!code) throw new SsoError("The provider sent no code back.");
      const doc = p.kind === "oidc" ? await this.discover(p) : null;
      if (doc && query.get("iss") && query.get("iss") !== doc.issuer) throw new SsoError("The answer came from another issuer (iss).");
      const tokens = await this.exchange(p, doc, code, flow.verifier, this.urls(p, base).redirect);
      let claims;
      if (p.kind === "oidc") {
        if (!tokens.id_token) throw new SsoError("The provider sent no id_token (is the openid scope on?).");
        claims = { ...(await this.verifyIdToken(p, doc, tokens.id_token, flow.nonce)) };
        // more about you (groups, a verified email) when the provider has a userinfo endpoint; the same subject only
        if (doc.userinfo_endpoint && tokens.access_token) {
          try {
            const ui = await fetchJson(this.f, doc.userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` } }, "The userinfo endpoint");
            if (ui.sub === claims.sub) for (const [k, v] of Object.entries(ui)) if (claims[k] === undefined) claims[k] = v;
          } catch (e) { this.log("sso:", p.id, "userinfo:", e.message); }
        }
      } else claims = await this.userinfo(p, tokens);
      return { flow, claims, identity: claimsIdentity(claims, p) };
    } catch (e) { e.flow = flow; throw e; }
  }
  async exchange(p, doc, code, verifier, redirect) {
    const secret = p.secret ? this.box.open(p.secret) : null;
    if (p.secret && secret == null) throw new SsoError("The client secret can't be read any more (secret.key changed?): paste it again in Settings → Sign-in.", "config");
    const methods = doc?.token_endpoint_auth_methods_supported || ["client_secret_basic"];
    const how = !secret ? "none" : p.tokenAuth && p.tokenAuth !== "auto" ? p.tokenAuth : p.kind === "oauth2" ? "post" : methods.includes("client_secret_basic") ? "basic" : "post";
    const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirect, code_verifier: verifier });
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (how === "basic") headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(p.clientId)}:${encodeURIComponent(secret)}`).toString("base64")}`;
    else { body.set("client_id", p.clientId); if (how === "post") body.set("client_secret", secret); }
    const j = await fetchJson(this.f, doc ? doc.token_endpoint : p.tokenUrl, { method: "POST", headers, body: body.toString() }, "The token endpoint");
    if (j.error) throw new SsoError(`The token endpoint said ${clean(j.error, 60)}${j.error_description ? `: ${clean(j.error_description, 200)}` : ""}`);
    if (!j.access_token && !j.id_token) throw new SsoError("The token endpoint sent no token.");
    return j;
  }
  // OAuth 2.0 without OIDC: who you are, from the userinfo endpoint (GitHub: and your verified primary email)
  async userinfo(p, tokens) {
    if (!tokens.access_token) throw new SsoError("The token endpoint sent no access_token.");
    const auth = { Authorization: `Bearer ${tokens.access_token}` };
    const ui = await fetchJson(this.f, p.userinfoUrl, { headers: auth }, "The userinfo endpoint");
    if (p.emailsUrl) {
      const list = await fetchJson(this.f, p.emailsUrl, { headers: auth }, "The emails endpoint").catch(() => []);
      const ok = (Array.isArray(list) ? list : []).filter((e) => e && e.verified);
      const best = ok.find((e) => e.primary) || ok[0];
      if (best) { ui.email = best.email; ui.email_verified = true; } else { ui.email_verified = false; }
    }
    return ui;
  }
  // SAML: the HTTP-POST answer (form fields SAMLResponse, RelayState)
  async acs(p, { base, form, bind, loose = false }) {
    this.sweep();
    const raw = String(form.SAMLResponse || "");
    if (!raw) throw new SsoError("No SAMLResponse in the request.");
    if (raw.length > MAX_SAML * 1.4) throw new SsoError("The SAMLResponse is too large.");
    const xml = Buffer.from(raw.replace(/\s+/g, ""), "base64").toString("utf8");
    const idp = await this.idpOf(p);
    const u = this.urls(p, base);
    const relay = typeof form.RelayState === "string" && form.RelayState ? form.RelayState : null;
    let flow = relay ? this.flows.get(relay) : null;
    let r;
    try { r = verifySamlResponse(xml, { idp, sp: { acs: u.acs, entityId: u.entityId }, allowSha1: !!p.allowSha1, now: this.now(), skew: this.skew }); }
    catch (e) { if (flow && flow.pid === p.id) { this.flows.delete(relay); e.flow = flow; } throw e; }
    if (r.inResponseTo) {
      // an answer to one of our requests: that one, unused, from this browser
      const hit = [...this.flows.entries()].find(([, f]) => f.reqId === r.inResponseTo && f.pid === p.id);
      if (!hit) throw new SsoError("This answer isn't for a sign-in started here, or it was already used.", "expired");
      if (relay && relay !== hit[0]) throw new SsoError("The RelayState doesn't match the request this answers.", "expired");
      flow = this.take(hit[0], p, bind, { loose });
    } else {
      if (!p.idpInitiated) throw new SsoError("An unsolicited answer (IdP-initiated sign-in) is off for this provider: start from the sign-in page.");
      flow = { pid: p.id, kind: "saml", next: "/", test: null };
    }
    if (this.seen.has(r.id)) { const e = new SsoError("This assertion was already used.", "expired"); e.flow = flow; throw e; }
    this.seen.set(r.id, r.until + this.skew * 1000);
    return { flow, claims: { nameId: r.nameId, nameIdFormat: r.nameIdFormat, issuer: r.issuer, ...r.attrs }, identity: samlIdentity(r, p) };
  }

  // ---- test sign-ins (Settings → Sign-in → Test): the popup's flow, and what came back
  testStart(pid) {
    this.sweep();
    const token = b64u(randomBytes(18));
    this.tests.set(token, { pid, exp: this.now() + TEST_TTL_MS, result: null });
    return token;
  }
  testOk(token, pid) { const t = this.tests.get(token); return !!t && t.pid === pid && !t.result && t.exp > this.now(); }
  testDone(token, result) { const t = this.tests.get(token); if (t) t.result = { at: this.now(), ...result }; }
  testResult(token) { const t = this.tests.get(token); return t ? { pid: t.pid, done: !!t.result, ...(t.result || {}) } : null; }
}

// Claims trimmed for the dashboard: no tokens, nothing huge.
export function showClaims(c) {
  const out = {};
  for (const [k, v] of Object.entries(c || {})) {
    if (/^(at_hash|c_hash|nonce|sid|access_token|id_token|refresh_token)$/.test(k)) continue;
    const s = JSON.stringify(v);
    out[k] = s && s.length > 600 ? `${s.slice(0, 600)}…` : v;
  }
  return out;
}
