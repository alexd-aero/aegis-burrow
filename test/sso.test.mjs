// Single sign-on (aegis/sso.mjs): a fake OpenID Connect provider in this
// process (discovery, JWKS, the token endpoint; RS256 and ES256 keys) run
// through the whole flow, and SAML answers signed here with xml-crypto by a
// keypair and a self-signed certificate made for the test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as csign, randomBytes } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { Sso, SsoError, secretBox, allowed, jwtSignedBy, checkIdClaims, verifySamlResponse, parseIdpMetadata, samlAlgorithms, SAML_SIG, SAML_DIGEST, NS } from "../aegis/sso.mjs";
import { SignedXml } from "../aegis/vendor/saml.mjs";
import { scopeFor } from "../aegis/apikeys.mjs";

const b64u = (b) => Buffer.from(b).toString("base64url");
const store = () => ({ data: {}, get(k) { return this.data[k]; }, set(p) { this.data = { ...this.data, ...p }; } });
const box = secretBox(randomBytes(32));
const BASE = "https://aegis.example.com";
const BIND = "browser-one";

// ------------------------------------------------------------------ a fake OIDC provider
function jwt(header, claims, key) {
  const data = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  const alg = header.alg;
  const sig = alg === "ES256" ? csign("sha256", Buffer.from(data), { key, dsaEncoding: "ieee-p1363" })
    : alg === "EdDSA" ? csign(null, Buffer.from(data), key)
    : alg === "PS256" ? csign("sha256", Buffer.from(data), { key, padding: 6, saltLength: 32 })
    : csign(alg.replace("RS", "sha"), Buffer.from(data), key);
  return `${data}.${b64u(sig)}`;
}
async function fakeIdp() {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }), ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keys = [{ ...rsa.publicKey.export({ format: "jwk" }), kid: "rsa1", use: "sig", alg: "RS256" },
                { ...ec.publicKey.export({ format: "jwk" }), kid: "ec1", use: "sig", alg: "ES256" }];
  const P = { codes: new Map(), keys, priv: { rsa1: rsa.privateKey, ec1: ec.privateKey }, alg: "RS256", kid: "rsa1", tweak: (c) => c, sigTweak: null,
              jwksHits: 0, tokenCalls: [], clientId: "aegis-client", secret: "s3cret-value-xyz" };
  const srv = createServer(async (req, res) => {
    const u = new URL(req.url, P.iss);
    let body = "";
    for await (const c of req) body += c;
    const json = (o, st = 200) => { res.writeHead(st, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };
    if (u.pathname === "/.well-known/openid-configuration") {
      return json({ issuer: P.iss, authorization_endpoint: `${P.iss}/authorize`, token_endpoint: `${P.iss}/token`, jwks_uri: `${P.iss}/jwks`,
                    userinfo_endpoint: `${P.iss}/userinfo`, token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"] });
    }
    if (u.pathname === "/jwks") { P.jwksHits++; return json({ keys: P.keys }); }
    if (u.pathname === "/authorize") {
      // the person signs in: a code bound to the PKCE challenge and the nonce
      const code = b64u(randomBytes(12));
      P.codes.set(code, { challenge: u.searchParams.get("code_challenge"), nonce: u.searchParams.get("nonce"), redirect: u.searchParams.get("redirect_uri"), client: u.searchParams.get("client_id") });
      res.writeHead(302, { Location: `${u.searchParams.get("redirect_uri")}?code=${code}&state=${encodeURIComponent(u.searchParams.get("state"))}` });
      return res.end();
    }
    if (u.pathname === "/token") {
      const f = new URLSearchParams(body), c = P.codes.get(f.get("code"));
      P.tokenCalls.push({ auth: req.headers.authorization || null, body: Object.fromEntries(f) });
      P.codes.delete(f.get("code"));
      const basic = req.headers.authorization ? Buffer.from(req.headers.authorization.slice(6), "base64").toString().split(":").map(decodeURIComponent) : [f.get("client_id"), f.get("client_secret")];
      if (!c || basic[0] !== P.clientId || basic[1] !== P.secret) return json({ error: "invalid_client" }, 401);
      if (b64u(createHash("sha256").update(f.get("code_verifier") || "").digest()) !== c.challenge) return json({ error: "invalid_grant", error_description: "PKCE" }, 400);
      if (f.get("redirect_uri") !== c.redirect) return json({ error: "invalid_grant", error_description: "redirect_uri_mismatch" }, 400);
      const now = Math.floor(Date.now() / 1000);
      const claims = P.tweak({ iss: P.iss, aud: P.clientId, sub: "user-42", email: "owner@example.com", email_verified: true, name: "The Owner",
                               groups: ["admins"], iat: now, exp: now + 300, nonce: c.nonce });
      let t = jwt({ alg: P.alg, kid: P.kid, typ: "JWT" }, claims, P.priv[P.kid]);
      if (P.sigTweak) t = P.sigTweak(t);
      return json({ access_token: "at-" + b64u(randomBytes(8)), token_type: "Bearer", id_token: t, expires_in: 300 });
    }
    if (u.pathname === "/userinfo") return json({ sub: "user-42", locale: "en" });
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  P.iss = `http://127.0.0.1:${srv.address().port}`;
  P.close = () => srv.close();
  return P;
}
// a browser: follow the provider's redirect back, and read the callback's query
async function signIn(S, p, P, { bind = BIND, back = BIND, mangle = (q) => q } = {}) {
  const loc = await S.start(p, { base: BASE, next: "/home", bind });
  assert.ok(loc.startsWith(`${P.iss}/authorize?`));
  const r = await fetch(loc, { redirect: "manual" });
  const cb = new URL(r.headers.get("location"));
  assert.equal(cb.origin + cb.pathname, `${BASE}/__gate/sso/${p.id}/callback`);
  return S.callback(p, { base: BASE, query: mangle(cb.searchParams), bind: back });
}
const oidcSetup = async (extra = {}) => {
  const P = await fakeIdp(), settings = store();
  const S = new Sso({ settings, box, jwksMinMs: 0 });
  const p = await S.add({ preset: "oidc", issuer: P.iss, clientId: P.clientId, clientSecret: P.secret, allow: { emails: "owner@example.com" }, ...extra });
  return { P, S, p, settings };
};

test("OIDC: the whole flow (PKCE, state, nonce, RS256), and the secret is sealed", async () => {
  const { P, S, p, settings } = await oidcSetup();
  try {
    assert.ok(!JSON.stringify(settings.data).includes(P.secret), "the client secret is never written in the clear");
    assert.match(settings.data.sso.providers[0].secret, /^enc1:/);
    const r = await signIn(S, p, P);
    assert.equal(r.identity.sub, "user-42");
    assert.equal(r.identity.email, "owner@example.com");
    assert.equal(r.claims.locale, "en", "userinfo fills in the rest (same subject)");
    assert.equal(r.flow.next, "/home");
    assert.deepEqual(allowed(p, r.identity), { ok: true, by: "email" });
    assert.ok(P.tokenCalls[0].auth?.startsWith("Basic "), "client_secret_basic, as discovery offers it");
    assert.ok(P.tokenCalls[0].body.code_verifier, "the PKCE verifier goes to the token endpoint");
    // the same state twice: the second is refused
    const loc = await S.start(p, { base: BASE, bind: BIND });
    const cb = new URL((await fetch(loc, { redirect: "manual" })).headers.get("location"));
    await S.callback(p, { base: BASE, query: cb.searchParams, bind: BIND });
    await assert.rejects(S.callback(p, { base: BASE, query: cb.searchParams, bind: BIND }), (e) => e instanceof SsoError && e.code === "expired");
  } finally { P.close(); }
});

test("OIDC: ES256, and a key the cache doesn't know is fetched again", async () => {
  const { P, S, p } = await oidcSetup({ tokenAuth: "post" });
  try {
    await signIn(S, p, P);
    const hits = P.jwksHits;
    P.alg = "ES256"; P.kid = "ec1";
    const r = await signIn(S, p, P);
    assert.equal(r.identity.sub, "user-42");
    assert.equal(P.tokenCalls.at(-1).body.client_secret, P.secret, "client_secret_post when asked for");
    // the provider rolls a new RSA key: an unknown kid sends us back to the JWKS
    const fresh = generateKeyPairSync("rsa", { modulusLength: 2048 });
    P.keys.push({ ...fresh.publicKey.export({ format: "jwk" }), kid: "rsa2", use: "sig" });
    P.priv.rsa2 = fresh.privateKey; P.alg = "RS256"; P.kid = "rsa2";
    await signIn(S, p, P);
    assert.ok(P.jwksHits > hits, "the JWKS was fetched again for the new kid");
  } finally { P.close(); }
});

test("OIDC: bad state, another browser, wrong aud or iss, expired, wrong nonce and a bad signature are refused", async () => {
  const { P, S, p } = await oidcSetup();
  const no = (fn, code) => assert.rejects(fn, (e) => e instanceof SsoError && (!code || e.code === code));
  try {
    await no(signIn(S, p, P, { mangle: (q) => { q.set("state", "made-up"); return q; } }), "expired");
    await no(signIn(S, p, P, { back: "another-browser" }), "expired");
    await no(signIn(S, p, P, { back: null }), "expired");
    P.tweak = (c) => ({ ...c, aud: "someone-else" });
    await no(signIn(S, p, P));
    P.tweak = (c) => ({ ...c, aud: [P.clientId, "other"] });             // several audiences: azp must name us
    await no(signIn(S, p, P));
    P.tweak = (c) => ({ ...c, iss: "https://evil.example.com" });
    await no(signIn(S, p, P));
    P.tweak = (c) => ({ ...c, exp: Math.floor(Date.now() / 1000) - 600, iat: Math.floor(Date.now() / 1000) - 900 });
    await no(signIn(S, p, P), "expired");
    P.tweak = (c) => ({ ...c, exp: Math.floor(Date.now() / 1000) - 60 });   // inside the clock skew: fine
    await signIn(S, p, P);
    P.tweak = (c) => ({ ...c, iat: Math.floor(Date.now() / 1000) + 3600 });
    await no(signIn(S, p, P), "expired");
    P.tweak = (c) => ({ ...c, nonce: "not-the-one" });
    await no(signIn(S, p, P));
    P.tweak = (c) => c;
    P.sigTweak = (t) => { const [h, c, s] = t.split("."); const b = Buffer.from(s, "base64url"); b[10] ^= 1; return `${h}.${c}.${b64u(b)}`; };
    await no(signIn(S, p, P));
    // a payload changed under a good signature
    P.sigTweak = (t) => { const [h, , s] = t.split("."); return `${h}.${b64u(JSON.stringify({ sub: "admin" }))}.${s}`; };
    await no(signIn(S, p, P));
    // alg "none" and HS256 are never taken
    P.sigTweak = (t) => { const [, c] = t.split("."); return `${b64u(JSON.stringify({ alg: "none" }))}.${c}.`; };
    await no(signIn(S, p, P));
    P.sigTweak = (t) => { const [, c] = t.split("."); return `${b64u(JSON.stringify({ alg: "HS256", kid: "rsa1" }))}.${c}.${b64u(randomBytes(32))}`; };
    await no(signIn(S, p, P));
    P.sigTweak = null;
    // the provider says no
    const loc = await S.start(p, { base: BASE, bind: BIND });
    const state = new URL(loc).searchParams.get("state");
    await no(S.callback(p, { base: BASE, query: new URLSearchParams({ state, error: "access_denied" }), bind: BIND }), "cancelled");
  } finally { P.close(); }
});

test("OIDC: an identity off the allow list is refused; nobody is allowed by default", async () => {
  const { P, S, p } = await oidcSetup({ allow: {} });
  try {
    const r = await signIn(S, p, P);
    assert.equal(allowed(p, r.identity).ok, false, "deny everyone until the owner adds someone");
    assert.match(allowed(p, r.identity).why, /nobody is allowed yet/);
    const q = S.allow(p.id, "email", "someone-else@example.com");
    assert.equal(allowed(q, r.identity).ok, false);
    assert.equal(allowed(S.allow(p.id, "domain", "@Example.com"), r.identity).by, "domain");
    assert.equal(allowed({ allow: { subjects: ["user-42"] } }, r.identity).by, "subject");
    assert.equal(allowed({ allow: { groups: ["admins"] } }, r.identity).by, "group");
    // an email the provider doesn't call verified doesn't match an email rule (a subject still does)
    const unverified = { ...r.identity, emailVerified: false };
    assert.equal(allowed({ verifiedEmail: true, allow: { emails: ["owner@example.com"] } }, unverified).ok, false);
    assert.equal(allowed({ verifiedEmail: false, allow: { emails: ["owner@example.com"] } }, unverified).ok, true);
  } finally { P.close(); }
});

test("OIDC: the provider is checked before it is kept; signature algorithms", async () => {
  const P = await fakeIdp();
  try {
    const S = new Sso({ settings: store(), box });
    await assert.rejects(S.add({ preset: "oidc", issuer: P.iss + "/other", clientId: "x", clientSecret: "y" }), SsoError);
    await assert.rejects(S.add({ preset: "oidc", issuer: "http://idp.example.com", clientId: "x", clientSecret: "y" }), /https/);
    await assert.rejects(S.add({ preset: "oidc", issuer: P.iss, clientId: "x" }), /secret/);
    const g = await S.add({ preset: "oidc", issuer: P.iss, clientId: "x", tokenAuth: "none" });
    assert.equal(g.id, "oidc");
    assert.equal((await S.add({ preset: "oidc", issuer: P.iss, clientId: "x", tokenAuth: "none" })).id, "oidc-2");
  } finally { P.close(); }
  // PS256 and EdDSA, straight
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }), ed = generateKeyPairSync("ed25519");
  const c = { sub: "a" };
  assert.ok(jwtSignedBy(jwt({ alg: "PS256", kid: "p" }, c, rsa.privateKey), [{ ...rsa.publicKey.export({ format: "jwk" }), kid: "p" }]).ok);
  assert.ok(jwtSignedBy(jwt({ alg: "EdDSA" }, c, ed.privateKey), [{ ...ed.publicKey.export({ format: "jwk" }) }]).ok);
  assert.ok(!jwtSignedBy(jwt({ alg: "RS256" }, c, rsa.privateKey), [{ ...ed.publicKey.export({ format: "jwk" }) }]).ok, "a key of another type");
  // Google's two spellings of its issuer, and Entra's template
  const now = Math.floor(Date.now() / 1000), base = { aud: "c", sub: "s", iat: now, exp: now + 60, nonce: "n" };
  assert.ok(checkIdClaims({ ...base, iss: "accounts.google.com" }, { issuers: ["https://accounts.google.com", "accounts.google.com"], clientId: "c", nonce: "n" }));
  assert.ok(checkIdClaims({ ...base, iss: "https://login.microsoftonline.com/t1/v2.0", tid: "t1" }, { issuers: ["https://login.microsoftonline.com/{tenantid}/v2.0"], clientId: "c", nonce: "n" }));
  assert.throws(() => checkIdClaims({ ...base, iss: "https://login.microsoftonline.com/t2/v2.0", tid: "t1" }, { issuers: ["https://login.microsoftonline.com/{tenantid}/v2.0"], clientId: "c", nonce: "n" }));
});

test("OAuth 2.0 (GitHub-style): userinfo and the verified primary email", async () => {
  const srv = createServer(async (req, res) => {
    let body = ""; for await (const c of req) body += c;
    const json = (o) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };
    if (req.url.startsWith("/token")) return json(new URLSearchParams(body).get("client_secret") === "gh-secret" ? { access_token: "gho_x", token_type: "bearer" } : { error: "bad_verification_code" });
    if (req.headers.authorization !== "Bearer gho_x") { res.writeHead(401); return res.end("{}"); }
    if (req.url === "/user") return json({ id: 1234, login: "octo", name: "Octo Cat", email: null });
    if (req.url === "/user/emails") return json([{ email: "old@example.com", verified: false, primary: false }, { email: "octo@example.com", verified: true, primary: true }]);
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const at = `http://127.0.0.1:${srv.address().port}`;
  try {
    const S = new Sso({ settings: store(), box });
    const p = await S.add({ preset: "oauth2", authorizeUrl: `${at}/authorize`, tokenUrl: `${at}/token`, userinfoUrl: `${at}/user`, clientId: "gh", clientSecret: "gh-secret", allow: { subjects: "1234" } });
    S.patch(p.id, (x) => { x.emailsUrl = `${at}/user/emails`; });
    const q = S.get(p.id);
    const loc = new URL(await S.start(q, { base: BASE, bind: BIND }));
    assert.equal(loc.searchParams.get("code_challenge_method"), "S256");
    assert.equal(loc.searchParams.get("nonce"), null, "no nonce without OIDC");
    const r = await S.callback(q, { base: BASE, query: new URLSearchParams({ code: "c", state: loc.searchParams.get("state") }), bind: BIND });
    assert.deepEqual([r.identity.sub, r.identity.email, r.identity.emailVerified, r.identity.username], ["1234", "octo@example.com", true, "octo"]);
    assert.equal(allowed(q, r.identity).by, "subject");
  } finally { srv.close(); }
});

// ------------------------------------------------------------------ SAML
// A self-signed X.509 certificate, DER by hand (Node signs, but doesn't make certificates).
function der(tag, ...parts) {
  const body = Buffer.concat(parts), n = body.length;
  const len = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
const seq = (...p) => der(0x30, ...p);
function oid(s) {
  const a = s.split(".").map(Number), out = [40 * a[0] + a[1]];
  for (const v of a.slice(2)) { const b = []; let x = v; do { b.unshift(x & 127); x >>= 7; } while (x); out.push(...b.map((y, i) => (i < b.length - 1 ? y | 128 : y))); }
  return der(0x06, Buffer.from(out));
}
const utc = (d) => der(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
function selfSigned(keys, ec = false) {
  const alg = ec ? seq(oid("1.2.840.10045.4.3.2")) : seq(oid("1.2.840.113549.1.1.11"), Buffer.from([5, 0]));
  const name = seq(der(0x31, seq(oid("2.5.4.3"), der(0x0c, Buffer.from("Test IdP")))));
  const tbs = seq(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1, ...randomBytes(8)])), alg, name,
                  seq(utc(new Date(Date.now() - 86400e3)), utc(new Date(Date.now() + 86400e3))), name, keys.publicKey.export({ type: "spki", format: "der" }));
  const sig = csign("sha256", tbs, keys.privateKey);
  const cert = seq(tbs, alg, der(0x03, Buffer.concat([Buffer.from([0]), sig])));
  return `-----BEGIN CERTIFICATE-----\n${cert.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
}
const IDP = "https://idp.example.com/application/saml/aegis/metadata/";
function idpMetadata(cert) {
  const body = cert.replace(/-----[A-Z ]+-----|\s/g, "");
  return `<md:EntityDescriptor xmlns:md="${NS.md}" xmlns:ds="${NS.ds}" entityID="${IDP}"><md:IDPSSODescriptor protocolSupportEnumeration="${NS.samlp}">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/application/saml/aegis/sso/binding/post/"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/application/saml/aegis/sso/binding/redirect/"/>
  </md:IDPSSODescriptor></md:EntityDescriptor>`;
}
const iso = (ms) => new Date(Date.now() + ms).toISOString();
function samlResponse({ id = "_a" + randomBytes(8).toString("hex"), inResponseTo, acs, audience, nameId = "owner@example.com", issuer = IDP,
                        recipient = acs, notOnOrAfter = iso(300e3), notBefore = iso(-60e3), destination = acs }) {
  const irt = inResponseTo ? ` InResponseTo="${inResponseTo}"` : "";
  return `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="_r${randomBytes(8).toString("hex")}" Version="2.0" IssueInstant="${iso(0)}" Destination="${destination}"${irt}>`
    + `<saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`
    + `<saml:Assertion ID="${id}" Version="2.0" IssueInstant="${iso(0)}"><saml:Issuer>${issuer}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${recipient}"${irt}/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(0)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + `<saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/claims/Group"><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>`
    + `<saml:Attribute Name="http://goauthentik.io/2021/02/saml/username"><saml:AttributeValue>owner</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`
    + `</saml:Assertion></samlp:Response>`;
}
function signXml(xml, keyPem, certPem, { what = "Assertion", alg = SAML_SIG.rsa256, digest = SAML_DIGEST.sha256 } = {}) {
  const sx = new SignedXml({ privateKey: keyPem, publicCert: certPem, signatureAlgorithm: alg, canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" });
  const { sigs, digs } = samlAlgorithms(true);
  sx.SignatureAlgorithms = { ...sx.SignatureAlgorithms, ...sigs }; sx.HashAlgorithms = { ...sx.HashAlgorithms, ...digs };
  const el = `//*[local-name(.)='${what}']`;
  sx.addReference({ xpath: el, digestAlgorithm: digest, transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"] });
  sx.computeSignature(xml, { location: { reference: `${el}/*[local-name(.)='Issuer']`, action: "after" } });
  return sx.getSignedXml();
}
async function samlSetup(extra = {}) {
  const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const cert = selfSigned(keys), keyPem = keys.privateKey.export({ type: "pkcs8", format: "pem" });
  const S = new Sso({ settings: store(), box });
  const p = await S.add({ preset: "saml", source: "xml", metadataXml: idpMetadata(cert), allow: { emails: "owner@example.com" }, ...extra });
  const u = S.urls(p, BASE);
  // the browser goes to the IdP with an AuthnRequest: what did we ask?
  async function ask(bind = BIND) {
    const loc = new URL(await S.start(S.get(p.id), { base: BASE, next: "/x", bind }));
    assert.equal(loc.origin + loc.pathname, "https://idp.example.com/application/saml/aegis/sso/binding/redirect/");
    const req = inflateRawSync(Buffer.from(loc.searchParams.get("SAMLRequest"), "base64")).toString();
    return { id: /ID="([^"]+)"/.exec(req)[1], relay: loc.searchParams.get("RelayState"), req };
  }
  const post = (xml, relay, bind = BIND) => S.acs(S.get(p.id), { base: BASE, form: { SAMLResponse: Buffer.from(xml).toString("base64"), RelayState: relay }, bind });
  const make = (o) => samlResponse({ acs: u.acs, audience: u.entityId, ...o });
  return { S, p, u, keys, cert, keyPem, ask, post, make };
}

test("SAML: the IdP's metadata, the AuthnRequest and this SP's metadata", async () => {
  const { S, p, u, cert, ask } = await samlSetup();
  const m = parseIdpMetadata(idpMetadata(cert));
  assert.equal(m.entityId, IDP);
  assert.equal(m.ssoUrl, "https://idp.example.com/application/saml/aegis/sso/binding/redirect/");
  assert.equal(m.certs.length, 1);
  assert.equal(u.entityId, `${BASE}/__gate/sso/${p.id}/metadata`);
  assert.equal(u.acs, `${BASE}/__gate/sso/${p.id}/acs`);
  const { req } = await ask();
  assert.match(req, new RegExp(`AssertionConsumerServiceURL="${u.acs}"`));
  assert.match(req, /nameid-format:emailAddress/);
  const md = S.metadata(p, BASE);
  assert.match(md, new RegExp(`entityID="${u.entityId}"`));
  assert.match(md, new RegExp(`Location="${u.acs}"`));
  assert.throws(() => parseIdpMetadata('<!DOCTYPE x [<!ENTITY a "b">]><x/>'), /DOCTYPE/);
});

test("SAML: a signed assertion (or a signed response) is accepted", async () => {
  const { S, p, ask, post, make, keyPem, cert } = await samlSetup();
  const a = await ask();
  const r = await post(signXml(make({ inResponseTo: a.id }), keyPem, cert), a.relay);
  assert.equal(r.identity.sub, "owner@example.com");
  assert.equal(r.identity.email, "owner@example.com");
  assert.deepEqual(r.identity.groups, ["admins"]);
  assert.equal(r.identity.username, "owner");
  assert.equal(r.flow.next, "/x");
  assert.equal(allowed(S.get(p.id), r.identity).by, "email");
  // the whole response signed instead
  const b = await ask();
  assert.equal((await post(signXml(make({ inResponseTo: b.id }), keyPem, cert, { what: "Response" }), b.relay)).identity.sub, "owner@example.com");
  // ECDSA (Robo Accounts can sign with it)
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const ecCert = selfSigned(ec, true);
  const E = await samlSetup();
  E.S.patch(E.p.id, (x) => { x.metadataXml = idpMetadata(ecCert); x.idp = { ...parseIdpMetadata(x.metadataXml), at: Date.now() }; });
  const c = await E.ask();
  const ecXml = signXml(E.make({ inResponseTo: c.id }), ec.privateKey.export({ type: "pkcs8", format: "pem" }), ecCert, { alg: SAML_SIG.ec256 });
  assert.equal((await E.post(ecXml, c.relay)).identity.sub, "owner@example.com");
});

test("SAML: tampered, wrapped, wrong audience or recipient, expired, unsolicited, sha1 and replays are refused", async () => {
  const { S, p, ask, post, make, keyPem, cert, u } = await samlSetup();
  const no = async (xml, relay, re) => assert.rejects(post(xml, relay), (e) => e instanceof SsoError && (!re || re.test(e.message)));
  // tampered: the NameID changed after signing
  let a = await ask();
  await no(signXml(make({ inResponseTo: a.id }), keyPem, cert).replace("owner@example.com</saml:NameID>", "admin@example.com</saml:NameID>"), a.relay, /verify/);
  // wrapped: an evil assertion next to the signed one, then the signed one tucked inside the evil one
  a = await ask();
  const good = signXml(make({ inResponseTo: a.id }), keyPem, cert);
  const signedAsr = /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(good)[0];
  const evil = signedAsr.replace(/ID="[^"]+"/, 'ID="_evil"').replace(/<Signature[\s\S]*<\/Signature>/, "").replace("owner@example.com</saml:NameID>", "admin@example.com</saml:NameID>");
  await no(good.replace(signedAsr, evil + signedAsr), a.relay, /more than one assertion/);
  await no(good.replace(signedAsr, evil.replace("</saml:Subject>", `</saml:Subject><saml:Advice>${signedAsr}</saml:Advice>`)), a.relay, /more than one assertion/);
  // the signature moved onto an assertion it doesn't cover
  const sigEl = /<Signature[\s\S]*<\/Signature>/.exec(good)[0];
  await no(good.replace(signedAsr, evil.replace("</saml:Issuer>", `</saml:Issuer>${sigEl}`)), a.relay);
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id, audience: "https://someone-else.example.com" }), keyPem, cert), a.relay, /audience/);
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id, recipient: "https://evil.example.com/acs" }), keyPem, cert), a.relay, /Recipient/);
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id, destination: "https://evil.example.com/acs" }), keyPem, cert), a.relay, /not this ACS/);
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id, notOnOrAfter: iso(-600e3), notBefore: iso(-900e3) }), keyPem, cert), a.relay, /expired/);
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id, issuer: "https://other-idp.example.com" }), keyPem, cert), a.relay, /issuer/);
  // unsigned, and signed by someone else
  a = await ask();
  await no(make({ inResponseTo: a.id }), a.relay, /signed/);
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id }), other.privateKey.export({ type: "pkcs8", format: "pem" }), selfSigned(other)), a.relay, /verify/);
  // an answer to a request never sent, and one with no request at all (IdP-initiated: off by default)
  await no(signXml(make({ inResponseTo: "_never-sent" }), keyPem, cert), undefined, /isn't for a sign-in started here/);
  await no(signXml(make({}), keyPem, cert), undefined, /unsolicited/i);
  // sha1: refused unless the provider allows it
  a = await ask();
  await no(signXml(make({ inResponseTo: a.id }), keyPem, cert, { alg: SAML_SIG.rsa1, digest: SAML_DIGEST.sha1 }), a.relay, /sha1/);
  // from another browser
  a = await ask();
  await assert.rejects(post(signXml(make({ inResponseTo: a.id }), keyPem, cert), a.relay, "another-browser"), /another browser/);
  // replayed: the same answer twice
  a = await ask();
  const once = signXml(make({ inResponseTo: a.id }), keyPem, cert);
  await post(once, a.relay);
  await no(once, a.relay);
  // allowed when the provider says so: IdP-initiated, and sha1
  S.patch(p.id, (x) => { x.idpInitiated = true; x.allowSha1 = true; });
  assert.equal((await post(signXml(make({}), keyPem, cert), undefined)).flow.next, "/");
  a = await ask();
  assert.ok(await post(signXml(make({ inResponseTo: a.id }), keyPem, cert, { alg: SAML_SIG.rsa1, digest: SAML_DIGEST.sha1 }), a.relay));
  // the verifier on its own: a DOCTYPE is never parsed
  assert.throws(() => verifySamlResponse(`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>${make({})}`, { idp: { entityId: IDP, certs: [cert] }, sp: { acs: u.acs, entityId: u.entityId } }), /DOCTYPE/);
});

test("SSO settings: SSO-only switches off with the last provider; no API key reaches /sso", async () => {
  const P = await fakeIdp();
  try {
    const S = new Sso({ settings: store(), box });
    const p = await S.add({ preset: "oidc", issuer: P.iss, clientId: "x", tokenAuth: "none" });
    S.setOptions({ only: true, base: "https://aegis.example.com/" });
    assert.deepEqual([S.conf().only, S.conf().base], [true, "https://aegis.example.com"]);
    assert.throws(() => S.setOptions({ base: "http://aegis.example.com" }), /https/);
    assert.throws(() => S.setOptions({ base: "https://aegis.example.com/path" }), /no path/);
    const v = S.view(S.get(p.id), BASE);
    assert.equal(v.secret, undefined);
    assert.equal(v.urls.redirect, `${BASE}/__gate/sso/oidc/callback`);
    S.remove(p.id);
    assert.equal(S.conf().only, false, "never SSO-only with nothing to sign in with");
    // a test sign-in's token works once, for that provider only
    const t = S.testStart("oidc");
    assert.ok(S.testOk(t, "oidc"));
    assert.ok(!S.testOk(t, "google"));
    S.testDone(t, { ok: true });
    assert.ok(!S.testOk(t, "oidc"));
    assert.equal(S.testResult(t).done, true);
  } finally { P.close(); }
  for (const [m, path] of [["GET", "/sso"], ["POST", "/sso/break-glass"], ["POST", "/sso/only"], ["PATCH", "/sso/providers/google"]]) assert.equal(scopeFor(m, path), "never", `${m} ${path}`);
});
