# The Aegis × Burrow API

Everything the dashboard and the `aegis` command line do, over HTTPS, with an API key.
Make keys in **Settings → Developer** (or `aegis keys create` on the machine).

```
https://<your dashboard>/__gate/v1/…
Authorization: Bearer aegis_<id>_<secret>        (or  X-Aegis-Key: aegis_…)
```

- Bodies and answers are JSON. Errors come as `{"error": "…"}` with the status:
  `400` bad request · `401` no key, wrong key, expired · `403` switched off, wrong address, or
  missing scope (then `need` names it) · `404` no such call · `413` body over 64 MB · `429` rate limit (`Retry-After`).
- Keys go in a header, never in a link. Aegis keeps only a SHA-256 of the secret: a lost key can't be shown
  again, only rolled (a new secret) or revoked.
- No key can see or make keys, change the login, or reach a root job's password prompt, whatever its scopes.
  So a leaked key never locks you out: revoke it in Settings → Developer.
- Every change a key makes lands in Settings → Activity (`aegis audit`) with the key's name, and in the key's
  own activity list (Settings → Developer → Activity, `aegis keys log`).
- Signed in to the dashboard, the same calls work from its own pages: that is the playground in Settings → Developer.

## Scopes

| Scope | What it may do |
|---|---|
| `full` | Everything below, and every app. Same as you signed in (but no keys, no login). |
| `read` | Every `GET`. Any writing scope can read too. |
| `tunnels` | `/tunnels…`, `/ports`, `/module` (Burrow on or off) |
| `addons` | `/addons…`, `/x/<addon>/…` (an addon's own API), `/bridge…`, `/integrations…` |
| `machines` | `/fleet…` (Machine management) |
| `network` | `/cf…`, `/domains…`, `/dns`, `/relay…`, `/serveo`, `/shield…`, `/ipintel/<ip>` |
| `system` | anything else: `/update…`, `/themes…`, `/backdrops…`, `/prefs`, `/termix…`, `/notices…`, `/pack` |
| `apps` | open apps behind the login with the key (below); no API calls on its own |

A key can also have: an expiry, a list of addresses or ranges it works from (`203.0.113.7`, `10.0.0.0/8`,
`2001:db8::/32`), and a rate limit (requests a minute, default 600, `0` = none).

## Opening apps with a key

With `full` or `apps`, the same header opens:

- **tunnels set to "login"** (and "password" ones): `curl https://app.example.com/ -H "Authorization: Bearer $AEGIS_KEY"`
- **apps under the dashboard** (Bulwark, Termix or Selkies Forge under a path)
- **Termix at the dashboard's root**, when it lives there

A key can open every app, or only the ones you pick (`tunnel:<port>`, `app:<id>`). Aegis takes the key off the
request before the app sees it; an app's own `Authorization` (Basic, its own tokens) passes through untouched.
WebSockets work the same way.

## Calls

`GET /__gate/v1/` (or `/whoami`) says who you are and what the key may do.

### Status
| Call | |
|---|---|
| `GET /overview` | version, login, domain(s), Burrow, Termix, Forge, updates: the `aegis status` block |
| `GET /status` | Burrow's engine: on, mode, tunnel counts |
| `GET /me` | what the dashboard's pages read: modules, apps, notices, update |
| `GET /audit` | the audit log (sign-ins, changes, with addresses) |
| `GET /notices` · `POST /notices/read {ids \| all}` · `POST /notices/clear` | the bell |

### Tunnels (Burrow)
| Call | |
|---|---|
| `GET /tunnels` | every tunnel, with its address, access, traffic, the domains it can live on |
| `POST /tunnels` | publish: `{port, name?, sub?, access?: "login"\|"password"\|"public", password?, domain?, targetHost?, targetPort?, scheme?}` |
| `GET /tunnels/<port>` | one tunnel, with its clients |
| `PATCH /tunnels/<port>` | change: `{name, sub, access, password, enabled, domains, targetHost, targetPort, scheme, ipChecks, preserveHost}` |
| `DELETE /tunnels/<port>` | unpublish |
| `POST /tunnels/<port>/kick {ip?}` | drop its clients (or one address) |
| `POST /tunnels/<port>/scan` | run every client through the IP checks |
| `GET /tunnels/<port>/fallback` · `POST …` | what your VPS serves when this machine is down |
| `GET /ports` | listening ports on this machine, for picking one |
| `GET /tunnels/naming` · `PUT /tunnels/naming` | record per tunnel, or one wildcard; where visitors arrive |
| `POST /module {burrow: bool}` | Burrow on or off |

### Addons
| Call | |
|---|---|
| `GET /addons` · `GET /addons/updates` · `POST /addons/check` | installed, with updates |
| `POST /addons/add {source}` | add one from a link or a folder |
| `POST /addons/<id>/install\|update\|uninstall\|rollback\|check` | returns `{job}`; follow `GET /addons/jobs/<job id>` |
| `POST /addons/<id>/action {action}` | run one of its actions |
| `POST /addons/<id>/autorestart {on}` | restart it if it stops |
| `GET\|POST… /x/<id>/…` | the addon's own API (Burrow Pages, Bulwark…) |

Addons that need root answer `428` with what to send (`password`); a key can supply it like the dashboard does.

### Machines (Fleet)
| Call | |
|---|---|
| `GET /fleet` | linked machines and the hub |
| `POST /fleet/invite` · `POST /fleet/add` | link a machine (a one-time command), or add one by SSH |
| `GET\|PATCH\|DELETE /fleet/<m-id>` | one machine |
| `POST /fleet/<m-id>/probe\|verify\|install\|standby\|movegate\|termix` | probe, check, install an app, keep a standby copy… |
| `POST /fleet/transfer {app, from, to, mode, confirm}` · `POST /fleet/swap` | move or copy an app and its data |
| `GET /fleet/jobs/<id>` | follow a Fleet job |

### Network
| Call | |
|---|---|
| `GET /cf` · `POST /cf/login\|cancel\|link\|rename\|unlink` | the main domain through Cloudflare |
| `GET /domains` · `POST /domains` · `PATCH\|DELETE /domains/<zone>` · `POST /domains/<zone>/check` | other domains |
| `GET /relay` · `POST /relay/setup\|check\|forget` · `GET\|POST /relay/doctor` | your VPS relay |
| `GET /serveo` · `POST /serveo {on}` | the serveo link |
| `GET /shield` · `PUT /shield` · `POST /shield/ban\|unban\|allow\|disallow {ip}` · `GET /ipintel/<ip>` | the built-in shield |
| `GET /dns` | the domain's DNS records |

### System
| Call | |
|---|---|
| `GET /update` · `POST /update/check` · `POST /update/apply` | updates |
| `GET /update/versions` · `POST /update/rollback {version}` · `POST /update/hold {version}` | versions kept here |
| `GET /themes` · `POST /themes/inspect\|apply\|use\|remove` | Weft themes |
| `POST /prefs {title, home, sessionDays, lockout, modules, autoUpdate, …}` | preferences |
| `GET /termix` · `POST /termix/install\|remove` | Termix |
| `GET /pack` · `POST /pack` | the full pack |

## Examples

Ready-made clients and scripts are in [`examples/api`](../examples/api): curl, a Node.js client
(`aegis-api.mjs`, no packages) and a Python one (`aegis_api.py`, standard library only).

```sh
export AEGIS_URL=https://aegis.example.com AEGIS_KEY=aegis_…
curl -s $AEGIS_URL/__gate/v1/tunnels -H "Authorization: Bearer $AEGIS_KEY"
curl -s -X POST $AEGIS_URL/__gate/v1/tunnels -H "Authorization: Bearer $AEGIS_KEY" \
  -d '{"port": 8080, "name": "My app", "sub": "app", "access": "login"}'
```

## Managing keys

Only a signed-in person, or the machine's own user:

```sh
aegis keys                                     # list
aegis keys create "deploy bot" --scopes read,tunnels --expires 90
aegis keys create "home assistant" --read --ips 192.168.1.0/24 --rate 120
aegis keys create "everything" --full --apps all
aegis keys set "deploy bot" --apps 8080,termix --rate 0
aegis keys disable "deploy bot" | enable | roll | revoke   (revoke --all)
aegis keys off | on                            # the whole API
aegis keys log
```
