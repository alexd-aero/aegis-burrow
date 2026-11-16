// A client for the Aegis × Burrow API (docs/API.md). Node.js 18+, no packages.
//
//   import { Aegis } from "./aegis-api.mjs";
//   const aegis = new Aegis({ url: "https://aegis.example.com", key: "aegis_…" });   // or AEGIS_URL / AEGIS_KEY
//
// Run it for a little command line:  node aegis-api.mjs help
export class AegisError extends Error {
  constructor(status, body) { super(`${status}: ${body?.error || "request failed"}`); this.status = status; this.body = body; }
}

export class Aegis {
  constructor({ url = process.env.AEGIS_URL, key = process.env.AEGIS_KEY } = {}) {
    if (!url || !key) throw new Error("Give it the dashboard's address and a key (AEGIS_URL, AEGIS_KEY).");
    this.url = url.replace(/\/+$/, "");
    this.key = key;
  }
  // any call: aegis.call("GET", "/overview"), aegis.call("POST", "/tunnels", {port: 8080})
  async call(method, path, body) {
    const r = await fetch(`${this.url}/__gate/v1${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.key}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    let json;
    try { json = JSON.parse(text); } catch { json = { error: text.slice(0, 200) }; }
    if (!r.ok) throw new AegisError(r.status, json);
    return json;
  }
  whoami() { return this.call("GET", "/whoami"); }
  status() { return this.call("GET", "/overview"); }
  async tunnels() { return (await this.call("GET", "/tunnels")).tunnels; }
  tunnel(port) { return this.call("GET", `/tunnels/${port}`); }
  publish(port, { name, sub, access = "login", password, domain } = {}) {
    return this.call("POST", "/tunnels", { port, name, sub, access, password, domain });
  }
  change(port, patch) { return this.call("PATCH", `/tunnels/${port}`, patch); }
  unpublish(port) { return this.call("DELETE", `/tunnels/${port}`); }
  async addons() { return (await this.call("GET", "/addons")).addons; }
  async addonUpdates() { return (await this.call("GET", "/addons/updates")).updates; }
  // runs an addon job (install, update, uninstall, rollback, action) and waits for it
  async addonJob(id, op, body = {}) {
    const { job } = await this.call("POST", `/addons/${id}/${op}`, body);
    for (;;) {
      const j = await this.call("GET", `/addons/jobs/${job.id}`);
      if (j.state !== "running") return j;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  machines() { return this.call("GET", "/fleet"); }
  // an app behind the login (a tunnel set to "login", or one under the dashboard), opened with the key
  open(url, init = {}) { return fetch(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${this.key}` } }); }
}

// ---- the command line
if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd = "help", ...a] = process.argv.slice(2);
  const flag = (n, d) => { const i = a.indexOf(`--${n}`); return i >= 0 ? a.splice(i, 2)[1] : d; };
  const show = (x) => console.log(JSON.stringify(x, null, 2));
  try {
    const aegis = new Aegis();
    if (cmd === "whoami") show(await aegis.whoami());
    else if (cmd === "status") { const s = await aegis.status(); console.log(`${s.app} ${s.version} · ${s.mainHost || s.local} · ${s.burrow.tunnels} tunnels · update: ${s.update.available ? s.update.latest : "none"}`); }
    else if (cmd === "tunnels") for (const t of await aegis.tunnels()) console.log(`${String(t.port).padEnd(6)} ${(t.access || "login").padEnd(8)} ${t.enabled ? "on " : "off"} ${t.name || ""}  ${t.url || ""}`);
    else if (cmd === "publish") {
      const sub = flag("sub"), access = flag("access", "login");
      const t = await aegis.publish(Number(a[0]), { name: a[1], sub, access });
      console.log(`port ${t.port} → ${t.url || "(its address is on the way)"} (${t.access})`);
    }
    else if (cmd === "unpublish") { await aegis.unpublish(Number(a[0])); console.log(`port ${a[0]} unpublished`); }
    else if (cmd === "addons") for (const x of await aegis.addons()) console.log(`${x.id.padEnd(16)} ${x.version || ""}  ${x.running ? "running" : x.installed ? "installed" : "not installed"}`);
    else if (cmd === "update-addons") {
      const ups = await aegis.addonUpdates();
      if (!ups.length) console.log("every addon is up to date");
      for (const u of ups) { process.stdout.write(`updating ${u.id}… `); const j = await aegis.addonJob(u.id, "update"); console.log(j.state); }
    }
    else if (cmd === "open") { const r = await aegis.open(a[0]); console.log(r.status, r.headers.get("content-type")); console.log((await r.text()).slice(0, 400)); }
    else if (cmd === "call") show(await aegis.call(a[0], a[1], a[2] ? JSON.parse(a[2]) : undefined));
    else console.log(`node aegis-api.mjs whoami | status | tunnels | publish PORT [NAME] [--sub S] [--access login|password|public]
                   | unpublish PORT | addons | update-addons | open URL | call METHOD PATH [JSON]
  (AEGIS_URL and AEGIS_KEY say where and who)`);
  } catch (e) { console.error(`✗ ${e.message}`); process.exit(1); }
}
