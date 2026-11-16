# API examples

Small, dependency-free clients for the Aegis × Burrow API ([docs/API.md](../../docs/API.md)).
Make a key in **Settings → Developer** (or `aegis keys create NAME`), then:

```sh
export AEGIS_URL=https://aegis.example.com      # your dashboard
export AEGIS_KEY=aegis_…                         # the key, shown once
```

| File | What it is |
|---|---|
| [`curl.sh`](curl.sh) | the API from a shell: status, tunnels, publish, change, remove, addons |
| [`aegis-api.mjs`](aegis-api.mjs) | a Node.js 18+ client (`fetch`, no packages) and a little command line |
| [`aegis_api.py`](aegis_api.py) | the same in Python 3, standard library only |

```sh
node aegis-api.mjs whoami
node aegis-api.mjs tunnels
node aegis-api.mjs publish 8080 "My app" --sub app --access login
node aegis-api.mjs open https://app.example.com/        # an app behind the login, with the key
node aegis-api.mjs update-addons
node aegis-api.mjs call GET /overview

python3 aegis_api.py tunnels
python3 aegis_api.py publish 8080 "My app" --access public
python3 aegis_api.py unpublish 8080
```

Both also work as libraries:

```js
import { Aegis } from "./aegis-api.mjs";
const aegis = new Aegis();                        // AEGIS_URL / AEGIS_KEY, or new Aegis({ url, key })
const t = await aegis.publish(8080, { name: "My app", access: "login" });
console.log(t.url);
```

```python
from aegis_api import Aegis
aegis = Aegis()
for t in aegis.tunnels():
    print(t["port"], t["url"])
```
