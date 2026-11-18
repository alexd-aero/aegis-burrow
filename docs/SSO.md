# Single sign-on

Aegis × Burrow can put **"Sign in with Google"** (straight, or through **Auth0**), **Microsoft Entra ID**, **Okta**, **GitHub**, **Robo Accounts**, or any **OpenID Connect**, **OAuth 2.0** or **SAML 2.0** provider on its sign-in page, as buttons above the password.

Aegis has one owner, so a provider never creates accounts. It proves that the person at the browser is you, or someone you allowed. **Nobody gets in until you allow someone**, by exact email, email domain, subject (the provider's own ID for you) or group. A sign-in that gets through does exactly what the password does: a session for every tunnel, the device key, the shield trusts the address, and an entry in *Settings → Activity* naming the provider and who it was. A refused one is in Activity too, and counts toward the lockout like a wrong password.

Everything below is also in the dashboard, under **Settings → Sign-in → Sign in with…**. There, each provider has a **Set it up** panel with these steps and **copy buttons** for every URL, filled in with your own address.

- [How it works](#how-it-works)
- [The URLs you give a provider](#the-urls-you-give-a-provider)
- [Google](#google)
- [Auth0, and Google through Auth0](#auth0-and-google-through-auth0)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Okta](#okta)
- [GitHub](#github)
- [Robo Accounts (OpenID Connect)](#robo-accounts-openid-connect)
- [Robo Accounts (SAML)](#robo-accounts-saml)
- [Any OpenID Connect provider](#any-openid-connect-provider)
- [Any OAuth 2.0 provider](#any-oauth-20-provider)
- [Any SAML 2.0 IdP](#any-saml-20-idp)
- [Who may sign in](#who-may-sign-in)
- [SSO only, and getting back in](#sso-only-and-getting-back-in)
- [Troubleshooting](#troubleshooting)

## How it works

1. **Settings → Sign-in → Add a way to sign in**, pick the provider. The panel shows the steps for it and the URLs to paste at the provider.
2. Make the app or client at the provider, paste the URLs, and copy back what it gives you (a client ID and secret, a domain, a metadata URL).
3. **Add it.** Aegis asks the provider before keeping it (its discovery document, or its SAML metadata), so a typo shows up now, not at sign-in.
4. **Test sign-in.** A popup runs the real sign-in and shows what came back: subject, email (and whether the provider says it's verified), name, username, groups, and every claim or attribute. A test never signs anyone in.
5. Press **Allow** next to your email, your subject, your domain or a group. From then on the provider's button is on the sign-in page.

**Where callbacks go.** Every provider sends people back to the **main host** (your dashboard's address, like `https://aegis.example.com`), the same way login tunnels already sign in through it, so one sign-in still covers every tunnel. Without a linked domain, set the **sign-in address** at the top of the section: any `https://` name that reaches this dashboard (a Tailscale name works), or `http://localhost:PORT` to try it on this machine.

**What Aegis checks.**

- *OpenID Connect:* the authorization code flow with **PKCE (S256)**, a **state** and a **nonce** kept on the server for ten minutes and bound to the browser that started the sign-in. The code is exchanged with `client_secret_basic` or `client_secret_post` (whichever the discovery document offers, or the one you pick). The **id_token's signature** is checked against the provider's JWKS (RS256, RS384, RS512, PS256, ES256, ES384, EdDSA; never `none` or HMAC), then `iss`, `aud` and `azp`, `exp`, `iat` and `nbf` with two minutes of clock skew, and the nonce. The JWKS is cached for an hour and fetched again for a key ID it doesn't know (keys rotate).
- *OAuth 2.0 (no id_token, like GitHub):* the same flow; who you are comes from the userinfo endpoint with the access token.
- *SAML 2.0:* an AuthnRequest over HTTP-Redirect; the answer over HTTP-POST at the ACS URL. The **XML signature** (on the Response, on the Assertion, or both: one valid one is enough) must be by one of the IdP's certificates, checked with [xml-crypto](https://github.com/node-saml/xml-crypto). Who you are is read **only from the XML that signature covers**, and an answer with more than one assertion is refused, so signature wrapping gets nowhere. Then the Issuer, Destination and Recipient (this ACS URL), Audience (this SP's entity ID), NotBefore and NotOnOrAfter (two minutes of skew), and InResponseTo (an answer to a request this Aegis sent, once). SHA-1 is refused unless you allow it for that provider; IdP-initiated sign-in is off unless you switch it on. Encrypted assertions aren't supported: switch encryption off at the IdP (the signature still protects the assertion, and the browser only ever talks to your own HTTPS address).
- Client secrets are kept in `data/state.json` sealed with AES-256-GCM under a key derived from the gate's `secret.key`. No API key can see or change single sign-on (`/__gate/v1/sso` answers 403 to every key).

## The URLs you give a provider

With `<main host>` your dashboard's address and `<id>` the provider's ID in Aegis (the panel shows the real ones):

| What | URL |
|---|---|
| Redirect / callback URL (OIDC, OAuth 2.0) | `https://<main host>/__gate/sso/<id>/callback` |
| Logout URL (if asked) | `https://<main host>/__gate/login` |
| Web origin (if asked) | `https://<main host>` |
| ACS URL (SAML, HTTP-POST) | `https://<main host>/__gate/sso/<id>/acs` |
| SP entity ID / Audience (SAML) | `https://<main host>/__gate/sso/<id>/metadata` |
| SP metadata (SAML) | `https://<main host>/__gate/sso/<id>/metadata` |

The ID is the provider's kind (`google`, `auth0`, `entra`, `okta`, `github`, `robo`, `robo-saml`, `oidc`, `oauth2`, `saml`), with `-2`, `-3` for a second one of the same kind.

## Google

Google directly, with your own OAuth client in Google Cloud.

1. Open [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) and pick or create a project.
2. If Google asks, set up the **OAuth consent screen** (Google Auth Platform → Branding): an app name and your email. Audience **External**. While the app is in *Testing*, add your own Google account under **Test users** (or publish it: the scopes Aegis asks for, `openid email profile`, need no review).
3. **Create credentials → OAuth client ID**, application type **Web application**, name it *Aegis*.
4. Under **Authorized redirect URIs**, **Add URI**: `https://<main host>/__gate/sso/google/callback`. No *Authorized JavaScript origins* are needed: Aegis talks to Google from the server.
5. **Create**, and copy the **Client ID** and **Client secret** into Aegis.
6. Save, **Test sign-in**, and **Allow** your Google email.

Aegis uses the issuer `https://accounts.google.com`, the scopes `openid email profile`, and only takes emails Google marks as verified (`email_verified`). It adds `prompt=select_account`, so you can pick the account.

## Auth0, and Google through Auth0

1. In the [Auth0 Dashboard](https://manage.auth0.com/): **Applications → Applications → Create Application**, name *Aegis*, type **Regular Web Applications**, **Create**.
2. On its **Settings** tab, copy the **Domain** (like `your-tenant.us.auth0.com`), the **Client ID** and the **Client Secret** into Aegis.
3. Under **Application URIs**, paste exactly:
   - **Allowed Callback URLs:** `https://<main host>/__gate/sso/auth0/callback`
   - **Allowed Logout URLs:** `https://<main host>/__gate/login`
   - **Allowed Web Origins:** `https://<main host>`

   then **Save Changes**. Leave *Credentials → Authentication Method* on *Client Secret (Post)* or *Client Secret (Basic)*: Aegis picks one Auth0 offers. The id_token is RS256 (Auth0's default).
4. **Google through Auth0:** **Authentication → Social**, open **google-oauth2** (*Google / Gmail*), switch it on, and on its **Applications** tab switch on *Aegis*. Auth0's own development keys are for trying it out; for real use, put your own Google client ID and secret in that connection, and give Google the redirect URI `https://<your Auth0 domain>/login/callback` (not Aegis's). In Aegis, tick **Go straight to Google** to skip Auth0's own page (it sends `connection=google-oauth2`). Any other connection works the same way: name it under *Advanced → Auth0 connection*.
5. Save, **Test sign-in**, **Allow** your email (Auth0 passes on Google's `email_verified`).

Issuer: `https://<your Auth0 domain>/` (discovery at `https://<your Auth0 domain>/.well-known/openid-configuration`).

## Microsoft Entra ID

1. In the [Microsoft Entra admin center](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade): **App registrations → New registration**, name *Aegis*, **Accounts in this organizational directory only** (single tenant).
2. **Redirect URI:** platform **Web**, `https://<main host>/__gate/sso/entra/callback`. **Register**.
3. From **Overview**, copy the **Directory (tenant) ID** and the **Application (client) ID** into Aegis.
4. **Certificates & secrets → New client secret**: copy its **Value** (not the *Secret ID*) into Aegis. Note when it expires, and make a new one before then.
5. **Token configuration → Add optional claim → ID → email.** To allow by group, **Add groups claim** too (Entra sends the groups' object IDs).
6. Save, **Test sign-in**, **Allow** your email or your subject.

Issuer: `https://login.microsoftonline.com/<tenant>/v2.0`. Entra doesn't say whether an email is verified, so for a single tenant Aegis takes the email as your directory has it. With a multi-tenant app (`organizations` or `common` as the tenant), anyone's directory can put any email in its tokens: allow by **subject** there, not by email.

## Okta

1. In the Okta Admin Console: **Applications → Applications → Create App Integration**, **OIDC - OpenID Connect**, **Web Application**, **Next**.
2. Name *Aegis*, grant type **Authorization Code**, then:
   - **Sign-in redirect URIs:** `https://<main host>/__gate/sso/okta/callback`
   - **Sign-out redirect URIs:** `https://<main host>/__gate/login`

   Under **Assignments**, pick who may use it. **Save**.
3. Copy the **Client ID**, the **Client secret** and your **Okta domain** (like `dev-123456.okta.com`) into Aegis. *Require PKCE* may stay on.
4. **Authorization server:** leave it empty for Okta's org server (issuer `https://<okta domain>`), or `default` for the custom one (issuer `https://<okta domain>/oauth2/default`, with API Access Management). To allow by group, add a **groups claim** (*Sign On* tab → *OpenID Connect ID Token*), and add `groups` to the scopes under *Advanced* when the server needs it.
5. Save, **Test sign-in**, **Allow** your email.

## GitHub

GitHub has no OpenID Connect for signing in to apps, so it is an OAuth 2.0 preset.

1. On GitHub: [Settings → Developer settings → OAuth Apps → New OAuth App](https://github.com/settings/applications/new) (or one under your organization's settings).
2. **Homepage URL:** `https://<main host>`. **Authorization callback URL:** `https://<main host>/__gate/sso/github/callback`. **Register application**.
3. Copy the **Client ID**, then **Generate a new client secret** and copy it, into Aegis.
4. Save, **Test sign-in**, **Allow** your subject or your email.

Aegis asks for `read:user user:email`, reads `https://api.github.com/user` and your **verified primary email** from `https://api.github.com/user/emails`. The subject is your numeric GitHub user ID: it stays the same if you rename your account, so it's the best thing to allow.

## Robo Accounts (OpenID Connect)

Robo Accounts is authentik-compatible. In its admin interface:

1. **Applications → Providers → Create → OAuth2/OpenID Provider.** Name *Aegis*, client type **Confidential**.
2. **Redirect URIs/Origins:** *Strict*, `https://<main host>/__gate/sso/robo/callback`.
3. **Signing Key:** pick a certificate, so tokens are signed RS256 (or ES256). Without one, the provider signs with HS256 and the client secret, which Aegis refuses. Scopes: `openid email profile` (the defaults).
4. **Applications → Create:** a name, a **slug** (like `aegis`), and the provider you just made.
5. In Aegis: the **address** (like `accounts.example.com`), the **slug**, the **Client ID** and the **Client Secret**.

Aegis then uses:

| | |
|---|---|
| Issuer | `https://HOST/application/o/<slug>/` |
| Discovery | `https://HOST/application/o/<slug>/.well-known/openid-configuration` |
| Authorize, token, userinfo | `https://HOST/application/o/authorize/`, `/application/o/token/`, `/application/o/userinfo/` (from discovery) |
| PKCE | S256 |

Groups come in the `groups` claim. If the test shows your email as *not verified*, allow your **subject** instead, or (only if Robo Accounts has no open sign-up) untick *Advanced → Only trust emails the provider says are verified*.

## Robo Accounts (SAML)

1. **Applications → Providers → Create → SAML Provider** (or **SAML Provider from Metadata**, with the SP metadata URL below). Name *Aegis*.
   - **ACS URL:** `https://<main host>/__gate/sso/robo-saml/acs`
   - **Audience:** `https://<main host>/__gate/sso/robo-saml/metadata`
   - **Service Provider Binding:** *Post*
   - SP metadata, to import: `https://<main host>/__gate/sso/robo-saml/metadata`
2. **Advanced protocol settings:** a **Signing Certificate** with *Sign assertions* on; **signature algorithm RSA-SHA256** (the default; ECDSA and SHA-384/512 work too; SHA-1 only if you tick *Allow SHA-1 signatures* in Aegis); **NameID Property Mapping:** the email one, so the NameID is your email (format `emailAddress`); **no encryption certificate**. No verification certificate is needed: Aegis's requests aren't signed.
3. **Applications → Create:** a name, a **slug** (like `aegis`), and the SAML provider.
4. In Aegis: the **address** and the **slug**. Aegis reads `https://HOST/application/saml/<slug>/metadata/` by itself: the entity ID, the SSO URL (`/application/saml/<slug>/sso/binding/redirect/`) and the signing certificate. It reads it again every 12 hours, so a rotated certificate is picked up.

Robo Accounts sends `email`, `name`, `username` (`http://goauthentik.io/2021/02/saml/username`) and groups (`http://schemas.xmlsoap.org/claims/Group`) as attributes by default; Aegis reads those names, and the usual others.

## Any OpenID Connect provider

Keycloak, authentik, Zitadel, Authelia, Kanidm, Dex, Ory, AWS Cognito, GitLab…

1. Make a **confidential / web** client with the **authorization code** flow. Redirect URI: `https://<main host>/__gate/sso/oidc/callback`; a post-logout redirect URI, if it asks: `https://<main host>/__gate/login`.
2. Scopes `openid email profile`; id_tokens signed RS256/384/512, PS256, ES256/384 or EdDSA (not HS256).
3. In Aegis: the **issuer** (Aegis reads `<issuer>/.well-known/openid-configuration`), the **client ID** and the **client secret**. A public client works too: *Advanced → Client authentication → None* (PKCE only).
4. If the provider names its claims differently, set them under *Advanced* (subject, email, groups; a dotted path like `realm_access.roles` works).

## Any OAuth 2.0 provider

For providers without OpenID Connect.

1. Register an OAuth 2.0 client with the redirect URI `https://<main host>/__gate/sso/oauth2/callback`.
2. In Aegis: the **authorization**, **token** and **userinfo** URLs, the **client ID**, the **client secret**, and the scopes it needs to tell you who you are.
3. Under *Advanced*, name the fields of the userinfo answer if they aren't `sub` (or `id`) and `email` (and `email_verified`; without it, untick *Only trust emails the provider says are verified* or allow by subject).

## Any SAML 2.0 IdP

ADFS, Shibboleth, Keycloak, JumpCloud, OneLogin, Google Workspace, Entra (Enterprise apps)…

1. Add a SAML 2.0 service provider (relying party) with:
   - **ACS URL** (HTTP-POST): `https://<main host>/__gate/sso/saml/acs`
   - **Entity ID / Audience:** `https://<main host>/__gate/sso/saml/metadata`
   - or import the **SP metadata** from that same URL
2. **NameID format** `emailAddress` (or a persistent ID: then allow it as a subject); **sign the assertion** (or the response) with RSA-SHA256 or better; **no encryption**. Attributes, if it sends them: `email`, `name`, `groups` (the usual URIs and OIDs are read too; other names under *Advanced*).
3. In Aegis, the IdP: its **metadata URL**, or **paste its metadata XML**, or **by hand**: its SSO URL (HTTP-Redirect binding), its entity ID (issuer) and its signing certificate.

## Who may sign in

Per provider, four lists (one entry per line):

- **Emails:** exact, any case. Only counted when the provider says the email is verified (*Only trust emails…*, on by default for OpenID Connect; SAML IdPs are trusted for their own emails).
- **Email domains:** anyone `@example.com` (verified, as above).
- **Subjects:** the provider's own ID for a person (`sub`, a SAML NameID, a GitHub user ID). The safest choice: it can't be reused by someone else.
- **Groups:** when the provider sends groups.

All empty means nobody, and the provider's button stays off the sign-in page until someone is on a list. A **Test sign-in** shows exactly what to add, with an **Allow** button next to each.

## SSO only, and getting back in

The password stays on the sign-in page by default. **SSO only** hides it: the page shows just the buttons, and a password sent anyway is refused. It needs a provider that's on and lets someone in (test it first).

You can't lock yourself out:

- `aegis sso password on` on the machine puts the password form back (`aegis sso password off` hides it again).
- `aegis sso link` prints a **one-time link** (15 minutes) that shows the password form in that browser, even with SSO only.
- Switching off or removing the last provider that lets someone in switches SSO only off by itself.
- As a last resort, `"only": false` under `"sso"` in `~/.local/share/aegis/data/state.json`, then `aegis restart`.
- `aegis passwd` still sets a new password, and `aegis sso list` shows the providers.

## Troubleshooting

**`redirect_uri_mismatch` (Google), "Callback URL mismatch" (Auth0), `AADSTS50011` (Entra), "The redirect URI … is not valid" (others).** The provider doesn't know the callback URL Aegis sent. Paste the one from *Set it up* exactly: `https://`, the main host (not a local address, not a tunnel's), `/__gate/sso/<id>/callback`, no slash at the end. Google can take a few minutes to apply a change. If you renamed the dashboard (Settings → Domain), the URLs changed too: update them at the provider.

**"The id_token has expired", "issued in the future", "The assertion isn't valid yet / has expired".** The clocks differ by more than two minutes. Check this machine's with `timedatectl` (and switch on NTP: `sudo timedatectl set-ntp true`). A SAML assertion also expires if the sign-in took too long at the IdP: try again.

**"This sign-in expired or was already used" / "started in another browser".** The sign-in has ten minutes, works once, and must finish in the browser that started it. Opening the provider's page in another browser or app, a restart of Aegis in between, or the browser's back button does that. Start again from the button.

**`invalid_client`, `unauthorized_client`, "The client secret is missing".** The client ID or secret is wrong, or the secret expired (Entra's do). Copy them again. If the provider only takes one way of sending the secret, pick it under *Advanced → Client authentication*.

**"The discovery document is for issuer …".** The issuer you typed differs from what the provider calls itself. Use exactly the provider's (with or without the trailing slash as it writes it).

**"The id_token is signed with HS256, which isn't taken here".** The provider signs with the client secret instead of a key pair. Give it a signing certificate or key (Robo Accounts / authentik: the provider's *Signing Key*; Auth0: *Advanced Settings → OAuth → RS256*).

**"…signed in at the provider, but that account isn't allowed here."** The sign-in worked; the identity isn't on the provider's allow list. Run a **Test sign-in** and press **Allow**. If an email is listed but refused, the provider didn't say it's verified: allow the subject instead.

**SAML: "The signature doesn't verify…".** The IdP signs with another certificate than the one Aegis has (a rotated certificate: *Edit → Save* reads the metadata again), with SHA-1 (allow it under *Advanced* only if you must), or nothing is signed (switch on *Sign assertions*).

**SAML: "The assertion is for another audience", "Recipient isn't this ACS URL", "for … not this ACS URL".** The IdP has another entity ID or ACS URL than the ones in *Set it up*: paste them again.

**SAML: "An unsolicited answer…".** You started at the IdP's own app list. Start from Aegis's sign-in page, or switch on *Allow IdP-initiated sign-in* for that provider.

**SAML: "The assertion is encrypted".** Remove the encryption certificate at the IdP.

**"Too many attempts".** Failed sign-ins count toward the same lockout as wrong passwords (Settings → Sign-in → *Lock out after*). Wait, or sign in from another address.

**The button isn't on the sign-in page.** A provider shows up once it's switched on *and* someone is on its allow list, and only when Aegis has a sign-in address (a linked domain, or one you set).

**Everything else:** *Settings → Activity* lists every SSO sign-in, refusal and test with the provider's reason, and `aegis logs` has the same lines (`sso: …`).
