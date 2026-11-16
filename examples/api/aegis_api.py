"""A client for the Aegis x Burrow API (docs/API.md). Python 3.8+, standard library only.

    from aegis_api import Aegis
    aegis = Aegis(url="https://aegis.example.com", key="aegis_...")   # or AEGIS_URL / AEGIS_KEY

Run it for a little command line:  python3 aegis_api.py help
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request


class AegisError(Exception):
    def __init__(self, status, body):
        super().__init__(f"{status}: {body.get('error', 'request failed')}")
        self.status, self.body = status, body


class Aegis:
    def __init__(self, url=None, key=None):
        self.url = (url or os.environ.get("AEGIS_URL", "")).rstrip("/")
        self.key = key or os.environ.get("AEGIS_KEY", "")
        if not self.url or not self.key:
            raise ValueError("Give it the dashboard's address and a key (AEGIS_URL, AEGIS_KEY).")

    def call(self, method, path, body=None):
        """Any call: aegis.call("GET", "/overview"), aegis.call("POST", "/tunnels", {"port": 8080})"""
        req = urllib.request.Request(
            f"{self.url}/__gate/v1{path}", method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            try:
                err = json.load(e)
            except Exception:
                err = {"error": str(e)}
            raise AegisError(e.code, err) from None

    def whoami(self): return self.call("GET", "/whoami")
    def status(self): return self.call("GET", "/overview")
    def tunnels(self): return self.call("GET", "/tunnels")["tunnels"]
    def tunnel(self, port): return self.call("GET", f"/tunnels/{port}")

    def publish(self, port, name=None, sub=None, access="login", password=None, domain=None):
        spec = {"port": port, "name": name, "sub": sub, "access": access, "password": password, "domain": domain}
        return self.call("POST", "/tunnels", {k: v for k, v in spec.items() if v is not None})

    def change(self, port, **patch): return self.call("PATCH", f"/tunnels/{port}", patch)
    def unpublish(self, port): return self.call("DELETE", f"/tunnels/{port}")
    def addons(self): return self.call("GET", "/addons")["addons"]
    def addon_updates(self): return self.call("GET", "/addons/updates")["updates"]

    def addon_job(self, addon, op, body=None):
        """Runs an addon job (install, update, uninstall, rollback, action) and waits for it."""
        job = self.call("POST", f"/addons/{addon}/{op}", body or {})["job"]
        while True:
            j = self.call("GET", f"/addons/jobs/{job['id']}")
            if j["state"] != "running":
                return j
            time.sleep(1.5)

    def machines(self): return self.call("GET", "/fleet")

    def open(self, url, method="GET", data=None):
        """An app behind the login (a tunnel set to "login", or one under the dashboard), opened with the key."""
        req = urllib.request.Request(url, method=method, data=data, headers={"Authorization": f"Bearer {self.key}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()


def main(argv):
    cmd, args = (argv[0] if argv else "help"), argv[1:]

    def flag(name, default=None):
        if f"--{name}" in args:
            i = args.index(f"--{name}")
            value = args[i + 1]
            del args[i:i + 2]
            return value
        return default

    aegis = Aegis()
    if cmd == "whoami":
        print(json.dumps(aegis.whoami(), indent=2))
    elif cmd == "status":
        s = aegis.status()
        print(f"{s['app']} {s['version']} · {s.get('mainHost') or s['local']} · {s['burrow']['tunnels']} tunnels")
    elif cmd == "tunnels":
        for t in aegis.tunnels():
            print(f"{t['port']:<6} {t.get('access', 'login'):<8} {'on ' if t.get('enabled') else 'off'} {t.get('name') or ''}  {t.get('url') or ''}")
    elif cmd == "publish":
        sub, access = flag("sub"), flag("access", "login")
        t = aegis.publish(int(args[0]), name=args[1] if len(args) > 1 else None, sub=sub, access=access)
        print(f"port {t['port']} → {t.get('url') or '(its address is on the way)'} ({t['access']})")
    elif cmd == "unpublish":
        aegis.unpublish(int(args[0]))
        print(f"port {args[0]} unpublished")
    elif cmd == "update-addons":
        ups = aegis.addon_updates()
        print("every addon is up to date" if not ups else "")
        for u in ups:
            print(f"updating {u['id']}…", aegis.addon_job(u["id"], "update")["state"])
    elif cmd == "call":
        print(json.dumps(aegis.call(args[0], args[1], json.loads(args[2]) if len(args) > 2 else None), indent=2))
    else:
        print("python3 aegis_api.py whoami | status | tunnels | publish PORT [NAME] [--sub S] [--access login|password|public]\n"
              "                     | unpublish PORT | update-addons | call METHOD PATH [JSON]\n"
              "  (AEGIS_URL and AEGIS_KEY say where and who)")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (AegisError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)
