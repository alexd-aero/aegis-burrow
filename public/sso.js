// Settings → Sign-in → Sign in with…: single sign-on providers (aegis/sso.mjs).
// Add one from a preset (Google, Auth0, Microsoft Entra ID, Okta, GitHub, Robo
// Accounts, or any OpenID Connect, OAuth 2.0 or SAML provider), follow its "Set it
// up" steps (every URL to whitelist, with a copy button), test it in a popup, and
// allow who may sign in from what the test sent back. Nobody is allowed until then.
import { h, toast } from "./common.js";

const SS = { data: null, err: "", loading: false, open: null, draft: null, busy: false, formErr: "", test: null, editBase: false, rerender: () => {} };
const ORDER = ["google", "auth0", "entra", "okta", "github", "robo", "robo-saml", "oidc", "oauth2", "saml"];
const BLURB = {
  google: "Your Google account, straight from Google Cloud.", auth0: "An Auth0 tenant: Google and any other connection through it.",
  entra: "Microsoft work or school accounts (Azure AD).", okta: "An Okta organization.", github: "Your GitHub account (OAuth 2.0).",
  robo: "Robo Accounts over OpenID Connect.", "robo-saml": "Robo Accounts over SAML 2.0.",
  oidc: "Any OpenID Connect provider: Keycloak, authentik, Zitadel, Authelia…", oauth2: "A plain OAuth 2.0 provider with a userinfo endpoint.",
  saml: "Any SAML 2.0 IdP: ADFS, Shibboleth, Keycloak, JumpCloud…",
};
const ALLOW = [["emails", "Emails", "owner@example.com"], ["domains", "Email domains", "example.com"], ["subjects", "Subjects (the provider's ID for you)", "the subject from a test"], ["groups", "Groups", "admins"]];

async function call(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts, headers: { "X-Gate": "1", "Content-Type": "application/json", ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
async function loadSso() {
  try { SS.data = await call("/__gate/api/sso"); SS.err = ""; } catch (e) { SS.err = e.message; }
  SS.rerender();
}
const preset = (k) => SS.data?.presets?.[k] || { name: k, fields: [] };
const urlsFor = (id, kind) => {
  const at = `${SS.data.base}/__gate/sso/${id}`;
  return kind === "saml" ? { acs: `${at}/acs`, entityId: `${at}/metadata`, metadata: `${at}/metadata` } : { redirect: `${at}/callback`, logout: `${SS.data.base}/__gate/login`, origin: SS.data.base };
};
// the id a new provider gets (the server picks the same one)
function freeId(p) {
  const taken = new Set(SS.data.providers.map((x) => x.id));
  let id = p, n = 2;
  while (taken.has(id)) id = `${p}-${n++}`;
  return id;
}
const copyRow = (label, v) => `<div class="sso-copy"><span class="faint small">${h(label)}</span><div class="row"><input class="input mono sm" readonly value="${h(v)}"><button type="button" class="btn sm" data-sso="copy" data-v="${h(v)}">Copy</button></div></div>`;
const link = (href, text) => `<a class="link" href="${h(href)}" target="_blank" rel="noopener">${h(text)}</a>`;

// ------------------------------------------------------------------ the steps, per preset
// What to do at the provider, what to give it (copy buttons), and what to bring back.
function steps(kind, id, f = {}) {
  const k = preset(kind).kind, u = urlsFor(id, k);
  const domain = f.domain || "YOUR-TENANT.us.auth0.com", host = f.host || "accounts.example.com", slug = f.slug || "aegis";
  const finish = `<li>Save below, then <b>Test sign-in</b>: the popup shows what the provider sent back. Click <b>Allow</b> next to your email or subject. <b>Nobody gets in until you allow someone.</b></li>`;
  const S = {
    google: `<ol class="sso-steps">
      <li>Open ${link("https://console.cloud.google.com/apis/credentials", "Google Cloud Console → APIs & Services → Credentials")} and pick (or create) a project.</li>
      <li>If Google asks, set up the <b>OAuth consent screen</b> (Google Auth Platform → Branding): an app name, your email. Audience <b>External</b>; while it's in <i>Testing</i>, add your own Google account under <b>Test users</b>. The scopes Aegis asks for (openid, email, profile) need no review.</li>
      <li><b>Create credentials → OAuth client ID</b>, application type <b>Web application</b>, name it <i>Aegis</i>.</li>
      <li>Under <b>Authorized redirect URIs</b>, <b>Add URI</b> and paste exactly:${copyRow("Authorized redirect URI", u.redirect)}<span class="faint small">No Authorized JavaScript origins needed: Aegis talks to Google from the server.</span></li>
      <li><b>Create</b>, then copy the <b>Client ID</b> and <b>Client secret</b> into the form below.</li>${finish}</ol>
      <p class="faint small">Aegis only takes emails Google marks as verified (<span class="mono">email_verified</span>).</p>`,
    auth0: `<ol class="sso-steps">
      <li>In the ${link("https://manage.auth0.com/", "Auth0 Dashboard")}: <b>Applications → Applications → Create Application</b>, name <i>Aegis</i>, type <b>Regular Web Applications</b>, <b>Create</b>.</li>
      <li>On its <b>Settings</b> tab, copy the <b>Domain</b>, <b>Client ID</b> and <b>Client Secret</b> into the form below.</li>
      <li>Scroll to <b>Application URIs</b> and paste each exactly:
        ${copyRow("Allowed Callback URLs", u.redirect)}${copyRow("Allowed Logout URLs", u.logout)}${copyRow("Allowed Web Origins", u.origin)}
        then <b>Save Changes</b>. (Leave Credentials → Authentication Method on <i>Client Secret (Post)</i> or <i>Basic</i>; Aegis picks what Auth0 offers.)</li>
      <li><b>Google through Auth0:</b> <b>Authentication → Social</b>, open <b>google-oauth2</b> (Google / Gmail), switch it on and, on its <b>Applications</b> tab, switch on <i>Aegis</i>. For real use put your own Google client ID and secret in that connection (Auth0's dev keys are for testing); Google's redirect URI is then <span class="mono">https://${h(domain)}/login/callback</span>. Tick <b>Go straight to Google</b> below to skip Auth0's chooser.</li>${finish}</ol>`,
    entra: `<ol class="sso-steps">
      <li>In the ${link("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade", "Microsoft Entra admin center")}: <b>App registrations → New registration</b>, name <i>Aegis</i>, <b>Accounts in this organizational directory only</b> (single tenant).</li>
      <li><b>Redirect URI</b>: platform <b>Web</b>, then paste:${copyRow("Redirect URI (Web)", u.redirect)}<b>Register</b>.</li>
      <li>From <b>Overview</b>, copy the <b>Directory (tenant) ID</b> and the <b>Application (client) ID</b> into the form below.</li>
      <li><b>Certificates & secrets → New client secret</b>: copy its <b>Value</b> (not the Secret ID) into the form. Note when it expires: make a new one before then.</li>
      <li><b>Token configuration → Add optional claim → ID → email</b>; <b>Add groups claim</b> too if you'll allow by group (Entra sends group object IDs).</li>${finish}</ol>
      <p class="faint small">Entra doesn't say whether an email is verified, so for a single tenant Aegis takes its email as is. With a multi-tenant app (organizations, common) allow by <b>subject</b> instead.</p>`,
    okta: `<ol class="sso-steps">
      <li>In the Okta Admin Console: <b>Applications → Applications → Create App Integration</b>, <b>OIDC - OpenID Connect</b>, <b>Web Application</b>, <b>Next</b>.</li>
      <li>Name <i>Aegis</i>, grant type <b>Authorization Code</b>, then paste:${copyRow("Sign-in redirect URIs", u.redirect)}${copyRow("Sign-out redirect URIs", u.logout)}Under <b>Assignments</b>, pick who may use it. <b>Save</b>.</li>
      <li>Copy the <b>Client ID</b>, the <b>Client secret</b> and your <b>Okta domain</b> (like <span class="mono">dev-123456.okta.com</span>) into the form below. "Require PKCE" may stay on.</li>
      <li><b>Authorization server</b>: leave it empty for Okta's org server, or <span class="mono">default</span> for the custom one (API Access Management). To allow by group, add a <b>groups claim</b> (Sign On tab → OpenID Connect ID Token) and the <span class="mono">groups</span> scope.</li>${finish}</ol>`,
    github: `<ol class="sso-steps">
      <li>On GitHub: ${link("https://github.com/settings/applications/new", "Settings → Developer settings → OAuth Apps → New OAuth App")} (or one under your organization).</li>
      <li>Paste:${copyRow("Homepage URL", u.origin)}${copyRow("Authorization callback URL", u.redirect)}<b>Register application</b>.</li>
      <li>Copy the <b>Client ID</b>, then <b>Generate a new client secret</b> and copy it, into the form below.</li>${finish}</ol>
      <p class="faint small">GitHub signs in with OAuth 2.0 (no OpenID Connect): Aegis reads your profile and your verified primary email (scopes <span class="mono">read:user user:email</span>). The subject is your GitHub user ID: it stays the same if you rename.</p>`,
    robo: `<ol class="sso-steps">
      <li>In Robo Accounts (its admin interface): <b>Applications → Providers → Create → OAuth2/OpenID Provider</b>. Name <i>Aegis</i>, client type <b>Confidential</b>.</li>
      <li><b>Redirect URIs/Origins</b>: <i>Strict</i>, then paste:${copyRow("Redirect URI", u.redirect)}</li>
      <li><b>Signing Key</b>: pick a certificate (RS256 or ES256). Without one it signs with HS256, which Aegis refuses. Scopes: <span class="mono">openid email profile</span> (the default ones).</li>
      <li><b>Applications → Create</b>: a name, a <b>slug</b> (like <span class="mono">aegis</span>), and the provider you just made.</li>
      <li>Copy into the form below: the address (<span class="mono">${h(host)}</span>), the slug, the <b>Client ID</b> and the <b>Client Secret</b>. Aegis finds the rest at <span class="mono">https://${h(host)}/application/o/${h(slug)}/.well-known/openid-configuration</span> (PKCE S256).</li>${finish}</ol>
      <p class="faint small">Groups come in the <span class="mono">groups</span> claim. If the test shows your email as not verified, allow your <b>subject</b>, or untick "Only trust verified emails" if Robo Accounts has no open sign-up.</p>`,
    "robo-saml": `<ol class="sso-steps">
      <li>In Robo Accounts: <b>Applications → Providers → Create → SAML Provider</b> (or <b>SAML Provider from Metadata</b> with the SP metadata URL below). Name <i>Aegis</i>.</li>
      <li>Paste:${copyRow("ACS URL", u.acs)}${copyRow("Audience (SP entity ID)", u.entityId)}${copyRow("SP metadata URL", u.metadata)}<b>Service Provider Binding</b>: <i>Post</i>.</li>
      <li><b>Advanced protocol settings</b>: a <b>Signing Certificate</b>, <i>Sign assertions</i> on; signature algorithm <b>RSA-SHA256</b> (ECDSA and SHA-384/512 work too; SHA-1 only if you tick "Allow SHA-1" below); <b>NameID Property Mapping</b>: the email one (format emailAddress); <b>no encryption certificate</b>.</li>
      <li><b>Applications → Create</b>: a name, a <b>slug</b> (like <span class="mono">aegis</span>), and the SAML provider.</li>
      <li>Fill in the address and the slug below: Aegis reads <span class="mono">https://${h(host)}/application/saml/${h(slug)}/metadata/</span> by itself (the SSO URL and the signing certificate).</li>${finish}</ol>
      <p class="faint small">Robo Accounts sends email, name, username and groups (<span class="mono">http://schemas.xmlsoap.org/claims/Group</span>) as attributes by default.</p>`,
    oidc: `<ol class="sso-steps">
      <li>At your provider, make a <b>confidential / web</b> client with the <b>authorization code</b> flow (PKCE S256 is used if it supports it).</li>
      <li>Paste:${copyRow("Redirect / callback URL", u.redirect)}${copyRow("Post-logout redirect URL (if asked)", u.logout)}Scopes: <span class="mono">openid email profile</span>; an id_token signed RS256/384/512, PS256, ES256/384 or EdDSA.</li>
      <li>Copy the <b>issuer</b> (Aegis reads <span class="mono">ISSUER/.well-known/openid-configuration</span>), the <b>client ID</b> and the <b>client secret</b> into the form below.</li>${finish}</ol>`,
    oauth2: `<ol class="sso-steps">
      <li>At your provider, register an OAuth 2.0 client (authorization code flow) with:${copyRow("Redirect / callback URL", u.redirect)}</li>
      <li>Copy its <b>authorization</b>, <b>token</b> and <b>userinfo</b> URLs, the <b>client ID</b> and the <b>client secret</b> into the form below, and the scopes it needs to read who you are.</li>
      <li>Under <b>Advanced</b>, name the fields of the userinfo answer if they aren't <span class="mono">sub</span> (or <span class="mono">id</span>) and <span class="mono">email</span>.</li>${finish}</ol>`,
    saml: `<ol class="sso-steps">
      <li>At your IdP, add a SAML 2.0 service provider (relying party) with:${copyRow("ACS URL (HTTP-POST)", u.acs)}${copyRow("Entity ID / Audience", u.entityId)}${copyRow("SP metadata URL (if it imports one)", u.metadata)}</li>
      <li>NameID format <b>emailAddress</b> (or a persistent ID: then allow it as a subject); <b>sign the assertion</b> (or the response) with RSA-SHA256 or better; <b>no encryption</b>. Attributes, if it sends them: <span class="mono">email</span>, <span class="mono">name</span>, <span class="mono">groups</span>.</li>
      <li>Bring back its <b>metadata URL</b> (or paste the metadata XML), or enter by hand its SSO URL (HTTP-Redirect binding), entity ID and signing certificate.</li>${finish}</ol>`,
  };
  return S[kind] || "";
}

// ------------------------------------------------------------------ the section
export function ssoBody() {
  const d = SS.data;
  if (!d) return `<div class="sso-sec" id="sso">${SS.err ? `<p class="err-msg">${h(SS.err)}</p>` : '<p class="muted"><i class="spin"></i> Loading…</p>'}</div>`;
  const baseRow = SS.editBase || !d.base ? `<form class="sso-base" id="ssoBaseForm">
        <label class="field grow"><span>Sign-in address <span class="faint">(where providers send people back: this dashboard's https:// address)</span></span>
          <input class="input mono" id="ssoBase" value="${h(d.baseSet || d.base || (d.here.startsWith("https://") ? d.here : ""))}" placeholder="https://aegis.example.com" spellcheck="false" autocapitalize="none"></label>
        <div class="row end" style="margin-top:0">${d.mainHost ? '<button type="button" class="btn ghost sm" data-sso="base-main">Use the main host</button>' : ""}${d.base ? '<button type="button" class="btn ghost sm" data-sso="base-cancel">Cancel</button>' : ""}<button class="btn sm">Save</button></div>
        ${d.base ? "" : '<p class="faint small">No domain is linked yet: providers need a fixed address to call back. Link one in Domain below, or give an https:// name that reaches this dashboard (a Tailscale name works; <span class="mono">http://localhost:PORT</span> for trying it on this machine).</p>'}</form>`
    : `<div class="dv-base"><span class="faint small">Sign-in address</span> <span class="mono">${h(d.base)}</span> <button type="button" class="btn sm ghost" data-sso="base-edit">Change</button></div>`;
  const list = d.providers.length ? `<div class="sso-list">${d.providers.map(providerCard).join("")}</div>` : "";
  const add = SS.draft ? draftView() : `<div class="sso-add"><p class="small"><b>Add a way to sign in</b></p><div class="sso-presets">${ORDER.map((k) => `
      <button type="button" class="sso-preset" data-sso="new" data-v="${k}">${preset(k).icon || ""}<span><b>${h(preset(k).name)}</b><span class="faint small">${h(BLURB[k] || "")}</span></span></button>`).join("")}</div></div>`;
  const anyAllowed = d.providers.some((p) => p.enabled && !p.nobody);       // what the sign-in page shows
  const only = `<div class="mod sso-only">
      <div class="grow"><b>SSO only</b> ${d.onlyActive ? '<span class="pill warn">password hidden</span>' : ""}
        <p class="muted small">Hide the password form: the sign-in page shows only the buttons. The password still works from this machine: <span class="mono">aegis sso password on</span> brings the form back, and <span class="mono">aegis sso link</span> makes a one-time link to it.${anyAllowed ? "" : " Switch on a provider that allows you (and test it) first."}</p></div>
      <label class="switch" title="${d.only ? "On" : "Off"}"><input type="checkbox" id="ssoOnly" ${d.only ? "checked" : ""} ${!d.only && !anyAllowed ? "disabled" : ""} aria-label="SSO only"><i></i></label></div>`;
  return `<div class="sso-sec" id="sso"><div class="od-head"><h3>Sign in with…</h3><p class="faint small">Google (straight, or through Auth0), Microsoft, Okta, GitHub, Robo Accounts, or any OpenID Connect, OAuth 2.0 or SAML provider, as buttons above the password.
      A provider doesn't make accounts: it proves it's you, or someone you allowed. Callbacks come to the main host, so one sign-in still covers every tunnel.</p></div>
    ${baseRow}${list}${add}${d.providers.length ? only : ""}</div>`;
}

function allowSummary(p) {
  const a = p.allow || {}, parts = [];
  if (a.emails?.length) parts.push(`${a.emails.length === 1 ? h(a.emails[0]) : `${a.emails.length} emails`}`);
  if (a.domains?.length) parts.push(`anyone @${h(a.domains.join(", @"))}`);
  if (a.subjects?.length) parts.push(`${a.subjects.length} ${a.subjects.length === 1 ? "subject" : "subjects"}`);
  if (a.groups?.length) parts.push(`group ${h(a.groups.join(", "))}`);
  return parts.join(" · ");
}
function providerCard(p) {
  const open = SS.open?.id === p.id ? SS.open.panel : null;
  const kindName = { oidc: "OpenID Connect", oauth2: "OAuth 2.0", saml: "SAML 2.0" }[p.kind];
  const body = open === "setup" ? `<div class="sso-panel"><p class="small"><b>Set it up</b> <span class="faint">· ${h(preset(p.preset).name)}</span></p>${steps(p.preset, p.id, p)}
        ${p.kind === "saml" && p.certs?.length ? `<p class="faint small">The IdP's signing certificate${p.certs.length > 1 ? "s" : ""}: ${p.certs.map((c) => `<span class="mono">${h(c.subject)}</span>, until ${h(new Date(c.notAfter).toLocaleDateString())}`).join("; ")}</p>` : ""}</div>`
    : open === "edit" ? `<div class="sso-panel">${form(SS.open.f, false)}</div>`
    : open === "test" ? `<div class="sso-panel">${testView(p)}</div>` : "";
  return `<div class="sso-card${p.enabled ? "" : " off"}" id="sso-${h(p.id)}">
    <div class="sso-card-head"><span class="sso-ico" aria-hidden="true">${preset(p.preset).icon || ""}</span>
      <div class="grow"><div class="row flexwrap" style="gap:8px"><b>${h(p.name)}</b><span class="pill">${kindName}</span>${!p.enabled ? '<span class="pill">off</span>' : p.nobody ? '<span class="pill">on, once someone is allowed</span>' : '<span class="pill ok"><i class="dot ok"></i>on the sign-in page</span>'}
        ${p.nobody ? '<span class="pill warn">nobody allowed yet</span>' : ""}</div>
        <p class="faint small" style="margin:4px 0 0">"${h(p.button)}" · ${p.nobody ? "test it, then allow yourself" : `lets in ${allowSummary(p)}`}${p.kind === "oidc" ? ` · <span class="mono">${h(p.issuerResolved || "")}</span>` : p.kind === "saml" && p.idp ? ` · <span class="mono">${h(p.idp.entityId)}</span>` : ""}</p></div>
      <label class="switch" title="${p.enabled ? "On" : "Off"}"><input type="checkbox" data-sso-on="${h(p.id)}" ${p.enabled ? "checked" : ""} aria-label="${h(p.name)} on the sign-in page"><i></i></label></div>
    <div class="sso-acts">
      <button type="button" class="btn sm${open === "setup" ? " on" : ""}" data-sso="panel" data-id="${h(p.id)}" data-v="setup">Set it up</button>
      <button type="button" class="btn sm${open === "test" ? " on" : ""}" data-sso="test" data-id="${h(p.id)}">Test sign-in</button>
      <button type="button" class="btn sm${open === "edit" ? " on" : ""}" data-sso="panel" data-id="${h(p.id)}" data-v="edit">Edit</button>
      <span class="grow"></span><button type="button" class="btn sm ghost danger" data-sso="remove" data-id="${h(p.id)}">Remove</button></div>
    ${body}</div>`;
}

// a form's values: from a provider (editing) or a preset's defaults (new)
function formOf(p) {
  const pr = preset(p.preset), a = p.allow || {};
  return { id: p.id, preset: p.preset, name: p.name || pr.name, button: p.buttonSet || "", domain: p.domain || "", tenant: p.tenant || "", authServer: p.authServer || "",
           host: p.host || "", slug: p.slug || "", issuer: p.issuer || "", authorizeUrl: p.authorizeUrl || "", tokenUrl: p.tokenUrl || "", userinfoUrl: p.userinfoUrl || "",
           clientId: p.clientId || "", clientSecret: "", hasSecret: !!p.hasSecret, scopes: p.scopes ?? pr.scopes, tokenAuth: p.tokenAuth || "auto",
           verifiedEmail: p.verifiedEmail ?? pr.verifiedEmail, connection: p.connection || "", claims: { ...(p.claims || {}) },
           source: p.source || "url", metadataUrl: p.metadataUrl || "", metadataXml: "", hasMetadataXml: !!p.hasMetadataXml, idpEntityId: p.idpEntityId || "", idpSsoUrl: p.idpSsoUrl || "", idpCert: "",
           hasCert: !!p.idpCert, nameIdFormat: p.nameIdFormat || "email", allowSha1: !!p.allowSha1, idpInitiated: !!p.idpInitiated, attrs: { ...(p.attrs || {}) },
           allow: Object.fromEntries(ALLOW.map(([k]) => [k, (a[k] || []).join("\n")])) };
}
const input = (key, label, f, { ph = "", mono = true, type = "text", hint = "" } = {}) => `<label class="field grow"><span>${label}${hint ? ` <span class="faint">${hint}</span>` : ""}</span>
  <input class="input${mono ? " mono" : ""}" data-ssof="${key}" type="${type}" value="${h(f[key] ?? "")}" placeholder="${h(ph)}" spellcheck="false" autocapitalize="none" autocomplete="off"></label>`;
const box = (key, label, f, hint = "") => `<label class="check"><input type="checkbox" data-ssob="${key}" ${f[key] ? "checked" : ""}> <span>${label}${hint ? ` <span class="faint small">${hint}</span>` : ""}</span></label>`;

function form(f, isNew) {
  const pr = preset(f.preset), kind = pr.kind, fields = pr.fields || [];
  const F = {
    domain: () => input("domain", f.preset === "okta" ? "Okta domain" : "Domain", f, { ph: f.preset === "okta" ? "dev-123456.okta.com" : "your-tenant.us.auth0.com" }),
    tenant: () => input("tenant", "Directory (tenant) ID", f, { ph: "00000000-0000-0000-0000-000000000000", hint: "(or a domain; organizations / common for multi-tenant)" }),
    authServer: () => input("authServer", "Authorization server", f, { ph: "empty: the org server", hint: "(optional: default for the custom one)" }),
    host: () => input("host", "Robo Accounts address", f, { ph: "accounts.example.com" }),
    slug: () => input("slug", "Application slug", f, { ph: "aegis" }),
    issuer: () => input("issuer", "Issuer", f, { ph: "https://id.example.com/realms/main" }),
    authorizeUrl: () => input("authorizeUrl", "Authorization URL", f, { ph: "https://id.example.com/oauth/authorize" }),
    tokenUrl: () => input("tokenUrl", "Token URL", f, { ph: "https://id.example.com/oauth/token" }),
    userinfoUrl: () => input("userinfoUrl", "Userinfo URL", f, { ph: "https://id.example.com/oauth/userinfo" }),
  };
  const where = fields.length ? `<div class="row flexwrap">${fields.map((k) => F[k]()).join("")}</div>` : "";
  const oauth = kind !== "saml" ? `<div class="row flexwrap">${input("clientId", "Client ID", f)}
      ${input("clientSecret", "Client secret", f, { type: "password", ph: f.hasSecret ? "kept: type to replace it" : "", hint: f.tokenAuth === "none" ? "(none: a public client)" : "" })}</div>
    ${f.preset === "auth0" ? `<label class="check"><input type="checkbox" data-sso="auth0-google" ${f.connection === "google-oauth2" ? "checked" : ""}> <span>Go straight to Google <span class="faint small">(sends connection=google-oauth2: skips Auth0's own page)</span></span></label>` : ""}
    <details class="adv"${f.preset === "oauth2" ? " open" : ""}><summary>Advanced</summary>
      <div class="row flexwrap">${input("scopes", "Scopes", f, { ph: pr.scopes })}
        <label class="field"><span>Client authentication</span><select class="input" data-ssof="tokenAuth">${[["auto", "Automatic"], ["basic", "client_secret_basic"], ["post", "client_secret_post"], ["none", "None (public client, PKCE)"]]
          .map(([v, l]) => `<option value="${v}" ${f.tokenAuth === v ? "selected" : ""}>${l}</option>`).join("")}</select></label></div>
      ${box("verifiedEmail", "Only trust emails the provider says are verified", f, "(email_verified; subjects and groups always count)")}
      ${f.preset === "auth0" ? input("connection", "Auth0 connection", f, { ph: "google-oauth2", hint: "(optional: always this one)" }) : ""}
      <p class="faint small">Claim names, if the provider's differ (empty: the usual ones):</p>
      <div class="row flexwrap">${["sub", "email", "groups"].map((k) => `<label class="field grow"><span>${k === "sub" ? "Subject" : k === "email" ? "Email" : "Groups"}</span>
        <input class="input mono" data-ssoc="${k}" value="${h(f.claims[k] || "")}" placeholder="${k === "sub" ? "sub (or id)" : k}" spellcheck="false" autocapitalize="none"></label>`).join("")}</div></details>`
    : `${f.preset === "robo-saml" ? "" : `<div class="field"><span>The IdP</span><div class="seg">${[["url", "Metadata URL"], ["xml", "Paste the metadata"], ["manual", "By hand"]]
          .map(([v, l]) => `<button type="button" data-sso="source" data-v="${v}" class="${f.source === v ? "on" : ""}">${l}</button>`).join("")}</div></div>
      ${f.source === "url" ? `<div class="row">${input("metadataUrl", "IdP metadata URL", f, { ph: "https://idp.example.com/metadata.xml" })}</div>`
        : f.source === "xml" ? `<label class="field"><span>IdP metadata XML ${f.hasMetadataXml ? '<span class="faint">(kept: paste to replace it)</span>' : ""}</span><textarea class="input mono" data-ssof="metadataXml" rows="5" spellcheck="false" placeholder="&lt;md:EntityDescriptor …">${h(f.metadataXml)}</textarea></label>`
        : `<div class="row flexwrap">${input("idpEntityId", "IdP entity ID (issuer)", f, { ph: "https://idp.example.com/saml" })}${input("idpSsoUrl", "SSO URL (HTTP-Redirect)", f, { ph: "https://idp.example.com/saml/sso" })}</div>
           <label class="field"><span>Signing certificate ${f.hasCert ? '<span class="faint">(kept: paste to replace it)</span>' : ""}</span><textarea class="input mono" data-ssof="idpCert" rows="4" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${h(f.idpCert)}</textarea></label>`}`}
      <details class="adv"><summary>Advanced</summary>
        <div class="field"><span>NameID format asked for</span><div class="seg">${[["email", "emailAddress"], ["any", "Any (unspecified)"]].map(([v, l]) => `<button type="button" data-sso="nameid" data-v="${v}" class="${f.nameIdFormat === v ? "on" : ""}">${l}</button>`).join("")}</div></div>
        ${box("allowSha1", "Allow SHA-1 signatures", f, "(old IdPs only: SHA-1 is broken)")}
        ${box("idpInitiated", "Allow IdP-initiated sign-in", f, "(unsolicited answers, from the IdP's own app list: off is safer)")}
        <p class="faint small">Attribute names, if the IdP's differ (empty: the usual ones, like email, mail, the emailaddress claim, groups):</p>
        <div class="row flexwrap">${["email", "groups"].map((k) => `<label class="field grow"><span>${k === "email" ? "Email" : "Groups"}</span>
          <input class="input mono" data-ssoa="${k}" value="${h(f.attrs[k] || "")}" spellcheck="false" autocapitalize="none"></label>`).join("")}</div></details>`;
  const allow = `<div class="field"><span>Who may sign in <span class="faint">(one per line; nobody until you add someone)</span></span>
      <div class="sso-allow">${ALLOW.map(([k, l, ph]) => `<label class="field"><span class="small">${l}</span><textarea class="input mono" data-ssol="${k}" rows="2" spellcheck="false" autocapitalize="none" placeholder="${h(ph)}">${h(f.allow[k])}</textarea></label>`).join("")}</div></div>`;
  return `<form class="sso-form" id="ssoForm" autocomplete="off">
    <div class="row flexwrap">${input("name", "Name", f, { mono: false })}${input("button", "Button text", f, { mono: false, ph: `Sign in with ${f.name || pr.name}` })}</div>
    ${where}${oauth}${allow}
    <div class="err-msg">${h(SS.formErr)}</div>
    <div class="row end"><button type="button" class="btn ghost" data-sso="${isNew ? "new-cancel" : "panel-close"}">Cancel</button>
      <button type="submit" class="btn primary" ${SS.busy ? "disabled" : ""}>${SS.busy ? `<i class="spin"></i> ${kind === "saml" ? "Reading the IdP…" : kind === "oidc" ? "Asking the provider…" : "Saving…"}` : isNew ? "Add it" : "Save"}</button></div>
  </form>`;
}

function draftView() {
  const f = SS.draft, pr = preset(f.preset);
  return `<div class="sso-card sso-new"><div class="sso-card-head"><span class="sso-ico" aria-hidden="true">${pr.icon || ""}</span>
      <div class="grow"><b>New: ${h(pr.name)}</b><p class="faint small" style="margin:2px 0 0">First at ${h(pr.name)}, then here.</p></div></div>
    <div class="sso-panel"><p class="small"><b>Set it up</b></p>${steps(f.preset, f.id, f)}</div>
    <div class="sso-panel">${form(f, true)}</div></div>`;
}

// what a test sign-in sent back, and buttons to allow it
function testView(p) {
  const t = SS.test?.id === p.id ? SS.test : null;
  if (!t) return "";
  if (!t.result) return `<p class="small"><i class="spin"></i> Waiting for the popup: sign in at ${h(p.name)} there.${t.url ? ` <a class="link" href="${h(t.url)}" target="_blank" rel="noopener">Open it again</a>` : ""}</p>`;
  const r = t.result;
  if (r.error) return `<div class="note-box note-err small"><b>The test failed.</b> ${h(r.error)}</div>${troubleHint(r.error)}`;
  const id = r.identity || {}, a = p.allow || {};
  const has = (k, v) => (a[k] || []).map((x) => String(x).toLowerCase()).includes(String(v).toLowerCase());
  const btn = (kind, v, label) => `<button type="button" class="btn sm${has(kind + "s", v) ? "" : " primary"}" data-sso="allow" data-id="${h(p.id)}" data-k="${kind}" data-v="${h(v)}" ${has(kind + "s", v) ? "disabled" : ""}>${has(kind + "s", v) ? "Allowed" : label}</button>`;
  const dom = id.email ? id.email.split("@")[1] : "";
  const rows = [["Subject", id.sub && `<span class="mono">${h(id.sub)}</span> ${btn("subject", id.sub, "Allow this subject")}`],
                ["Email", id.email && `<span class="mono">${h(id.email)}</span> ${id.emailVerified ? '<span class="pill ok">verified</span>' : '<span class="pill warn">not verified</span>'} ${btn("email", id.email, "Allow this email")} ${dom ? btn("domain", dom, `Allow anyone @${h(dom)}`) : ""}`],
                ["Name", id.name && h(id.name)], ["Username", id.username && `<span class="mono">${h(id.username)}</span>`],
                ["Groups", id.groups?.length && id.groups.map((g) => `<span class="mono">${h(g)}</span> ${btn("group", g, "Allow")}`).join(" ")]];
  return `<p class="small">${r.ok ? `<span class="pill ok">allowed</span> This account can sign in (by ${h(r.by)}).` : `<span class="pill warn">not allowed yet</span> ${h(r.why || "")}`}</p>
    <div class="sso-id">${rows.filter(([, v]) => v).map(([k, v]) => `<div class="kv-row"><span>${k}</span><span class="row flexwrap" style="gap:8px">${v}</span></div>`).join("")}</div>
    <details class="adv"><summary>Everything ${h(p.name)} sent</summary><pre class="dv-code">${h(JSON.stringify(r.claims || {}, null, 2))}</pre></details>
    <p class="faint small">No one was signed in by the test.</p>`;
}
function troubleHint(e) {
  const m = String(e);
  const tip = /redirect_uri|redirect uri|callback/i.test(m) ? "The provider doesn't know this callback URL: paste the one from Set it up exactly (https, the same host, no slash at the end)."
    : /clock|expired|not valid yet|future/i.test(m) ? "Check the clock on this machine (timedatectl) and the provider's: they may differ by at most 2 minutes."
    : /invalid_client|unauthorized_client|client secret/i.test(m) ? "The client ID or secret is wrong (or the secret expired): copy them again from the provider."
    : /audience|Recipient|ACS/i.test(m) ? "The IdP has another ACS URL or audience: paste the ones from Set it up."
    : /signature|certificate|sha1/i.test(m) ? "The IdP signs with another certificate, or with SHA-1: refresh its metadata (Edit → Save), or allow SHA-1 under Advanced if you must."
    : "";
  return tip ? `<p class="faint small" style="margin-top:8px">${h(tip)} More in docs/SSO.md → Troubleshooting.</p>` : "";
}

// ------------------------------------------------------------------ actions
function bodyOf(f, isNew) {
  const b = { name: f.name, button: f.button, allow: Object.fromEntries(ALLOW.map(([k]) => [k, f.allow[k]])) };
  if (isNew) { b.preset = f.preset; b.id = f.id; }
  for (const k of preset(f.preset).fields || []) b[k] = f[k];
  if (preset(f.preset).kind === "saml") {
    Object.assign(b, { source: f.source, nameIdFormat: f.nameIdFormat, allowSha1: f.allowSha1, idpInitiated: f.idpInitiated, attrs: f.attrs });
    if (f.source === "url") b.metadataUrl = f.metadataUrl;
    if (f.source === "xml" && f.metadataXml.trim()) b.metadataXml = f.metadataXml;
    if (f.source === "manual") { b.idpEntityId = f.idpEntityId; b.idpSsoUrl = f.idpSsoUrl; if (f.idpCert.trim()) b.idpCert = f.idpCert; }
  } else {
    Object.assign(b, { clientId: f.clientId, scopes: f.scopes, tokenAuth: f.tokenAuth, verifiedEmail: f.verifiedEmail, claims: f.claims });
    if (f.preset === "auth0") b.connection = f.connection;
    if (f.clientSecret) b.clientSecret = f.clientSecret;
  }
  return b;
}
async function save() {
  const isNew = !!SS.draft, f = isNew ? SS.draft : SS.open?.f;
  if (!f) return;
  SS.busy = true; SS.formErr = ""; SS.rerender();
  try {
    if (isNew) {
      SS.data = await call("/__gate/api/sso/providers", { method: "POST", body: JSON.stringify(bodyOf(f, true)) });
      SS.draft = null; SS.open = { id: SS.data.made, panel: "setup" };
      toast("Added. Now test it, and allow yourself.");
    } else {
      SS.data = await call(`/__gate/api/sso/providers/${f.id}`, { method: "PATCH", body: JSON.stringify(bodyOf(f, false)) });
      SS.open = null; toast("Saved");
    }
  } catch (e) { SS.formErr = e.message; }
  SS.busy = false; SS.rerender();
}
async function startTest(p) {
  try {
    const t = await call(`/__gate/api/sso/providers/${p.id}/test`, { method: "POST", body: "{}" });
    SS.test = { id: p.id, token: t.token, url: t.url, result: null, until: Date.now() + 10 * 60e3 };
    SS.open = { id: p.id, panel: "test" };
    SS.test.win = window.open(t.url, "aegis-sso-test", "width=520,height=720");
    if (!SS.test.win) toast("The popup was blocked: use the link to open it");
    SS.rerender();
    poll(SS.test);
  } catch (e) { toast(e.message); }
}
async function poll(t) {
  while (SS.test === t && !t.result && Date.now() < t.until) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const r = await call(`/__gate/api/sso/test/${t.token}`);
      if (r.done) {
        t.result = r;
        try { t.win?.close(); } catch { /* another origin may say no */ }
        if (SS.test === t) { await loadSso(); }
        return;
      }
    } catch (e) { t.result = { error: e.message }; SS.rerender(); return; }
  }
}
const copy = (v) => navigator.clipboard?.writeText(v).then(() => toast("Copied"), () => toast("Couldn't copy: select it and copy by hand"));

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-sso]");
  if (!el) return;
  const act = el.dataset.sso, id = el.dataset.id, p = id && SS.data?.providers.find((x) => x.id === id);
  if (act !== "copy" && act !== "auth0-google") document.activeElement?.blur?.();      // Settings never repaints under a focused field
  try {
    if (act === "copy") copy(el.dataset.v);
    else if (act === "new") { const k = el.dataset.v; SS.draft = { ...formOf({ preset: k }), id: freeId(k) }; SS.formErr = ""; SS.open = null; SS.rerender(); document.querySelector(".sso-new")?.scrollIntoView({ block: "start", behavior: "smooth" }); }
    else if (act === "new-cancel") { SS.draft = null; SS.formErr = ""; SS.rerender(); }
    else if (act === "panel") {
      const panel = el.dataset.v;
      SS.open = SS.open?.id === id && SS.open.panel === panel ? null : { id, panel, f: panel === "edit" ? formOf(p) : null };
      SS.formErr = ""; SS.rerender();
    }
    else if (act === "panel-close") { SS.open = null; SS.formErr = ""; SS.rerender(); }
    else if (act === "test") startTest(p);
    else if (act === "remove") {
      if (!confirm(`Remove ${p.name}? Its button leaves the sign-in page. (At ${p.name}, delete the app too.)`)) return;
      SS.data = await call(`/__gate/api/sso/providers/${id}`, { method: "DELETE" }); if (SS.open?.id === id) SS.open = null; toast(`${p.name} removed`); SS.rerender();
    }
    else if (act === "allow") {
      SS.data = await call(`/__gate/api/sso/providers/${id}/allow`, { method: "POST", body: JSON.stringify({ kind: el.dataset.k, value: el.dataset.v }) });
      toast(`Allowed: ${el.dataset.v}`);
      if (SS.test?.result && !SS.test.result.error) { const q = SS.data.providers.find((x) => x.id === id); SS.test.result.ok = true; SS.test.result.by = el.dataset.k; if (q?.nobody === false) SS.test.result.why = ""; }
      SS.rerender();
    }
    else if (act === "source" || act === "nameid") { const f = SS.draft || SS.open?.f; f[act === "source" ? "source" : "nameIdFormat"] = el.dataset.v; SS.rerender(); }
    else if (act === "auth0-google") { const f = SS.draft || SS.open?.f; f.connection = el.checked ? "google-oauth2" : ""; }
    else if (act === "base-edit") { SS.editBase = true; SS.rerender(); }
    else if (act === "base-cancel") { SS.editBase = false; SS.rerender(); }
    else if (act === "base-main") { SS.data = await call("/__gate/api/sso/options", { method: "POST", body: JSON.stringify({ base: null }) }); SS.editBase = false; toast("Providers call back to the main host"); SS.rerender(); }
  } catch (ex) { toast(ex.message); loadSso(); }
});

export function wireSso(rerender) {
  SS.rerender = rerender;
  if (!SS.data && !SS.loading) { SS.loading = true; loadSso().finally(() => { SS.loading = false; }); }
  const f = SS.draft || SS.open?.f;
  if (f) {
    document.querySelectorAll("[data-ssof]").forEach((x) => x.addEventListener("input", () => { f[x.dataset.ssof] = x.value; }));
    document.querySelectorAll("[data-ssof]").forEach((x) => x.tagName === "SELECT" && x.addEventListener("change", () => { f[x.dataset.ssof] = x.value; x.blur(); SS.rerender(); }));
    document.querySelectorAll("[data-ssob]").forEach((x) => x.addEventListener("change", () => { f[x.dataset.ssob] = x.checked; }));
    document.querySelectorAll("[data-ssoc]").forEach((x) => x.addEventListener("input", () => { f.claims[x.dataset.ssoc] = x.value.trim(); }));
    document.querySelectorAll("[data-ssoa]").forEach((x) => x.addEventListener("input", () => { f.attrs[x.dataset.ssoa] = x.value.trim(); }));
    document.querySelectorAll("[data-ssol]").forEach((x) => x.addEventListener("input", () => { f.allow[x.dataset.ssol] = x.value; }));
    // the steps name what you typed (Auth0's domain, Robo Accounts' address and slug): repaint once you leave the field
    document.querySelectorAll('[data-ssof="domain"], [data-ssof="host"], [data-ssof="slug"]').forEach((x) => x.addEventListener("change", () => { x.blur(); SS.rerender(); }));
  }
  document.getElementById("ssoForm")?.addEventListener("submit", (e) => { e.preventDefault(); save(); });
  document.getElementById("ssoBaseForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { SS.data = await call("/__gate/api/sso/options", { method: "POST", body: JSON.stringify({ base: document.getElementById("ssoBase").value.trim() || null }) }); SS.editBase = false; toast("Saved"); }
    catch (ex) { toast(ex.message); }
    document.activeElement?.blur(); SS.rerender();
  });
  document.querySelectorAll("[data-sso-on]").forEach((x) => x.addEventListener("change", async () => {
    const p = SS.data.providers.find((y) => y.id === x.dataset.ssoOn);
    try { SS.data = await call(`/__gate/api/sso/providers/${p.id}/toggle`, { method: "POST", body: JSON.stringify({ on: x.checked }) }); toast(x.checked ? `${p.name} is on the sign-in page` : `${p.name} is off`); }
    catch (ex) { toast(ex.message); }
    SS.rerender();
  }));
  document.getElementById("ssoOnly")?.addEventListener("change", async (e) => {
    const on = e.target.checked;
    if (on && !confirm("Hide the password form? Make sure a test sign-in says \"allowed\" first. To get the password back: aegis sso password on (or aegis sso link) on this machine.")) { e.target.checked = false; return; }
    try { SS.data = await call("/__gate/api/sso/options", { method: "POST", body: JSON.stringify({ only: on }) }); toast(on ? "SSO only: the password form is hidden" : "The password form is back"); }
    catch (ex) { toast(ex.message); }
    SS.rerender();
  });
}
// a busy form or a test waiting: keep the section as it is
export const ssoBusy = () => !!(SS.draft || SS.open?.panel === "edit" || (SS.test && !SS.test.result) || SS.busy);
