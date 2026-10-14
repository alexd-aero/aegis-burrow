// The shield: who may reach this machine at all. Every request to the gate,
// for a tunnel or the dashboard, goes past shield.gate(ip, …) first, and it
// answers in microseconds: nothing in it waits on the network.
//
//   blocklists  big public lists, downloaded every few hours and kept in
//               memory as sorted address ranges (feeds below). An address on a
//               "strong" list is banned on its first request.
//   payloads    requests that go looking for secrets or holes (/.env, /.git/,
//               ../../etc/passwd, phpunit's eval-stdin, ${jndi:…}) are dropped
//               (404, never reach the app) and scored. Two of those, or one
//               probe from an address with any other mark against it (a weaker
//               list, a scanner, Tor, spam reports), and it is banned.
//   lookups     every new address is also asked about in the background
//               (ipintel.mjs: GreyNoise, Spamhaus, DroneBL, StopForumSpam);
//               known-malicious ones are banned when the answer comes.
//
// A ban covers every tunnel and the dashboard, and closes what the address had
// open. You are never banned: private addresses, addresses that signed in to
// Aegis (the last 30 days), requests that carry a valid session, and an allow
// list of your own are let through whatever the lists say.
//
// data/shield/state.json keeps bans, the allow list, settings and counters;
// data/shield/feeds/ the last copy of each list, so a restart has them at once.

import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { isIP } from "node:net";

const HOUR = 3600e3, DAY = 24 * HOUR;
const UA = "Mozilla/5.0 (aegis-burrow shield)";
const GH = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/";

// strength: strong = banned on sight, weak = a mark against it (banned with a probe), info = shown only
export const FEEDS = [
  { id: "firehol1", name: "FireHOL level 1", url: GH + "firehol_level1.netset", strength: "strong", every: 6 * HOUR,
    about: "Spamhaus DROP/EDROP, DShield top attackers, Feodo and other botnet controllers" },
  { id: "firehol2", name: "FireHOL level 2", url: GH + "firehol_level2.netset", strength: "strong", every: 6 * HOUR,
    about: "attacks seen in the last two days (blocklist.de, DShield, GreenSnow)" },
  { id: "blocklistde", name: "blocklist.de", url: "https://lists.blocklist.de/lists/all.txt", strength: "strong", every: 6 * HOUR,
    about: "addresses reported for attacks on SSH, mail, web logins and more, IPv6 too" },
  { id: "cins", name: "CINS Army", url: "https://cinsscore.com/list/ci-badguys.txt", strength: "strong", every: 6 * HOUR,
    about: "the worst-scoring addresses on Sentinel IPS sensors" },
  { id: "et", name: "Emerging Threats", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", strength: "strong", every: 6 * HOUR,
    about: "known compromised hosts" },
  { id: "ipsum", name: "IPsum", url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", strength: "weak", every: 12 * HOUR,
    about: "how many of 30+ blocklists name an address; 3 or more counts as strong",
    tier: (n) => (n >= 3 ? "strong" : "weak") },
  { id: "firehol3", name: "FireHOL level 3", url: GH + "firehol_level3.netset", strength: "weak", every: 12 * HOUR,
    about: "attacks seen in the last 30 days" },
  { id: "elsnet", name: "elsnet ban list", url: "https://vonweber.nl/cgi/blacklister.cgi", strength: "weak", every: 12 * HOUR, timeout: 90000,
    about: "the hosts and addresses elsnet.org has banned (vonweber.nl)", kind: "elsnet" },
  { id: "tor", name: "Tor exits", url: "https://check.torproject.org/torbulkexitlist", strength: "info", every: 3 * HOUR,
    about: "Tor exit nodes, per the Tor Project" },
];

// ------------------------------------------------------------------ addresses
export const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.)/.test(ip)
  || /^(::1?$|f[cd]|fe[89ab])/i.test(ip);
export const normIp = (ip) => String(ip || "").trim().replace(/^::ffff:(?=\d+\.)/i, "").toLowerCase();
const v4int = (ip) => { const p = ip.split("."); return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3]; };
// an IPv6 address as a BigInt
function v6big(ip) {
  let [head, tail] = ip.includes("::") ? ip.split("::") : [ip, null];
  const hp = head ? head.split(":") : [], tp = tail ? tail.split(":") : [];
  const groups = tail === null ? hp : [...hp, ...Array(8 - hp.length - tp.length).fill("0"), ...tp];
  let n = 0n;
  for (const g of groups) n = (n << 16n) + BigInt(parseInt(g || "0", 16));
  return n;
}

// A list's addresses: IPv4 as merged [start, end] ranges (binary search), IPv6
// as exact addresses and a few prefixes. add(entry, extra) takes "a.b.c.d",
// "a.b.c.d/n" or an IPv6 address or prefix.
export class RangeSet {
  constructor() { this.raw = []; this.v6 = new Map(); this.v6nets = []; this.extra = new Map(); this.count = 0; }
  add(entry, extra) {
    const [addr, bits] = entry.split("/");
    const v = isIP(addr);
    if (v === 4) {
      const n = bits === undefined ? 32 : Number(bits);
      if (!(n >= 0 && n <= 32)) return;
      const start = (v4int(addr) & (n === 0 ? 0 : (~0 << (32 - n)))) >>> 0;
      this.raw.push([start, start + 2 ** (32 - n) - 1]);
      if (extra !== undefined && n === 32) this.extra.set(start, extra);
    } else if (v === 6) {
      const n = bits === undefined ? 128 : Number(bits);
      if (n === 128) this.v6.set(v6big(addr.toLowerCase()), extra ?? true);
      else if (n >= 16 && n < 128) this.v6nets.push([v6big(addr.toLowerCase()) >> BigInt(128 - n), n]);
      else return;
    } else return;
    this.count++;
  }
  // sort and merge: lookups need it, and lists overlap a lot
  seal() {
    this.raw.sort((a, b) => a[0] - b[0]);
    const s = [], e = [];
    for (const [a, b] of this.raw) {
      if (s.length && a <= e[e.length - 1] + 1) { if (b > e[e.length - 1]) e[e.length - 1] = b; }
      else { s.push(a); e.push(b); }
    }
    this.start = Float64Array.from(s); this.end = Float64Array.from(e);
    this.raw = null;
    return this;
  }
  // false, or true / the extra stored with that exact address
  has(ip) {
    if (isIP(ip) === 4) {
      const x = v4int(ip), S = this.start;
      let lo = 0, hi = S.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (S[mid] <= x) lo = mid + 1; else hi = mid - 1;
      }
      if (hi < 0 || x > this.end[hi]) return false;
      return this.extra.get(x) ?? true;
    }
    if (isIP(ip) === 6) {
      const n = v6big(ip);
      if (this.v6.has(n)) return this.v6.get(n);
      for (const [pre, bits] of this.v6nets) if (n >> BigInt(128 - bits) === pre) return true;
    }
    return false;
  }
}

// What a list's text says: one RangeSet per strength (IPsum's counts split it).
export function parseFeed(feed, text) {
  const sets = {};
  const put = (strength, entry, extra) => (sets[strength] ||= new RangeSet()).add(entry, extra);
  if (feed.kind === "elsnet") {
    const plain = text.replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ");
    const re = /(?:^|\s)(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)\s+(\d{4})\/(\d{2})\/(\d{2})-(\d{2}:\d{2}:\d{2})\s+(\d+)(?=\s)/g;
    for (let m; (m = re.exec(plain));) {
      if (isIP(m[2]) && !isPrivate(normIp(m[2]))) put(feed.strength, m[2], { host: m[1] === "-" ? null : m[1], since: `${m[3]}-${m[4]}-${m[5]} ${m[6]}`, hits: Number(m[7]) });
    }
  } else {
    for (const line of text.split("\n")) {
      const l = line.trim();
      if (!l || l[0] === "#" || l[0] === ";") continue;
      const [entry, n] = l.split(/[\s;,]+/);
      if (feed.tier) put(feed.tier(Number(n) || 1), entry, Number(n) || 1);
      else put(feed.strength, entry);
    }
  }
  for (const s of Object.values(sets)) s.seal();
  return sets;
}

// ------------------------------------------------------------------ payloads
// Looking for secrets or a way in: never a page anybody needs. Dropped (404).
const STRONG = [
  /(^|\/)\.env(\.[\w.-]*)?$/i, /(^|\/)\.(git|svn|hg|bzr)(\/|$)/i, /(^|\/)\.(aws|ssh|docker|kube|azure|gnupg)(\/|$)/i,
  /(^|\/)\.(npmrc|pypirc|netrc|htpasswd|htaccess|bash_history|zsh_history|ds_store|git-credentials|dockercfg|s3cfg)$/i,
  /(^|\/)\.vscode\/sftp\.json$/i, /(^|\/)sftp-config\.json$/i, /(^|\/)(id_rsa|id_ed25519|id_ecdsa)(\.pub)?$/i,
  /wp-config\.php/i, /(^|\/)(config|settings|database|secrets?|credentials)\.(ya?ml|ini|bak|old|sql|php\.bak|php~)$/i,
  /(^|\/)[\w.-]*\.(sql|sql\.gz|sqlite3?|bak|old|swp)$/i, /(^|\/)(backup|dump|db|database|site|www)\.(zip|tar|tar\.gz|tgz|rar|7z)$/i,
  /\.\.[\/\\]/, /%2e%2e/i, /%252e/i, /\/etc\/(passwd|shadow|hosts)/i, /\/proc\/self\//i, /win\.ini/i, /boot\.ini/i,
  /phpunit/i, /eval-stdin\.php/i, /\$\{jndi:/i, /\$\{(::-|env:|lower:|upper:)/i, /<script/i, /union(\s|%20|\+|\/\*.*\*\/)+select/i,
  /php:\/\/(input|filter)/i, /allow_url_include/i, /auto_prepend_file/i, /(;|%3b|\||%7c)\s*(wget|curl|sh|bash|nc|busybox|chmod)(\s|%20|\+)/i,
  /\$\((wget|curl|sh|echo|id)/i, /`(wget|curl|id)/i, /\/(boaform|GponForm|HNAP1|setup\.cgi|shell\?|tmUnblock\.cgi|hndUnblock\.cgi)/i,
  /\/cgi-bin\/.*(\.sh|bash|luci|;)/i, /\/(actuator\/(env|heapdump|gateway)|_ignition\/execute-solution|telescope\/requests)/i,
  /\/(solr\/admin|jmx-console|invoker\/JMXInvokerServlet|vendor\/laravel-filemanager|server-status)/i,
  /\/(aws|amazon|s3|gcp|firebase|stripe|twilio|sendgrid|mailgun)[-_.]?(credentials|config|keys?)\.(json|ya?ml|txt|env)/i,
];
// Asking for software that isn't here: a probe if anything else is against it.
const WEAK = [
  /\.(php\d?|phtml|asp|aspx|jsp|cgi|pl|do|action)(\?|$)/i, /(^|\/)(wp-login|wp-admin|xmlrpc)/i, /(^|\/)(phpmyadmin|pma|myadmin|mysql|adminer)(\/|$)/i,
  /(^|\/)(manager\/html|owa|ecp|autodiscover|remote\/login|dana-na|global-protect|vpn|geoserver|druid|console|nacos|jenkins)(\/|$)/i,
  /(^|\/)(cgi-bin|scripts|webdav|HNAP1|portal|sdk|onvif|ReportServer|api\/jsonws|level\/15|mgmt)(\/|$)/i,
];
// 3: a payload (dropped), 1: a probe, 0: nothing. path: the request's path and query, as sent.
export function classify(path) {
  let p = String(path || "");
  let d = p;
  try { d = decodeURIComponent(p); } catch { /* bad escapes: test it as it is */ }
  const bare = d.split("?")[0];
  for (const re of STRONG) if (re.test(bare) || re.test(d) || re.test(p)) return 3;
  for (const re of WEAK) if (re.test(bare)) return 1;
  return 0;
}

// ------------------------------------------------------------------ the shield
export class Shield {
  // remote(ip, {probe}) -> Promise<ipintel result>; onBan(ip, ban): close its connections
  constructor({ dataDir, log, remote, onBan, fetchImpl } = {}) {
    this.dir = join(dataDir, "shield");
    mkdirSync(join(this.dir, "feeds"), { recursive: true });
    this.log = log || console.log;
    this.remote = remote || null;
    this.onBan = onBan || null;
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.lists = new Map();        // feed id -> {strong?, weak?, info?: RangeSet}
    this.scores = new Map();       // ip -> {score, probes, paths[], first, last}
    this.verdicts = new Map();     // ip -> {at, level, why[], bad}
    this.queued = new Map();       // ip -> when it was last sent to the lookups
    this.queue = [];
    this.running = 0;
    this.quiet = new Map();        // "ip|act" -> last event time (repeat blocks don't flood the log)
    this.timers = [];
    this.state = { settings: { auto: true, drop: true, lookups: true }, bans: {}, allow: {}, trusted: {}, feeds: {},
                   stats: { blocked: 0, dropped: 0, banned: 0, checked: 0, since: Date.now() }, events: [] };
    try {
      const s = JSON.parse(readFileSync(this.file(), "utf8"));
      this.state = { ...this.state, ...s, settings: { ...this.state.settings, ...s.settings }, stats: { ...this.state.stats, ...s.stats } };
    } catch { /* first run */ }
    this.dirty = false;
  }
  file() { return join(this.dir, "state.json"); }
  get settings() { return this.state.settings; }

  // lists from disk now, from the network when they're due; the state saved now and then
  start() {
    for (const f of FEEDS) this.loadFeed(f);
    const tick = () => this.refreshDue().catch((e) => this.log("shield: feeds:", e.message));
    this.timers.push(setTimeout(tick, 3000), setInterval(tick, 15 * 60e3), setInterval(() => this.save(), 30000));
    for (const t of this.timers) t.unref?.();
    return this;
  }
  stop() { for (const t of this.timers) { clearTimeout(t); clearInterval(t); } this.timers = []; this.save(); }
  save(force) {
    if (!this.dirty && !force) return;
    const now = Date.now();
    for (const [ip, b] of Object.entries(this.state.bans)) if (b.until && b.until < now) delete this.state.bans[ip];
    for (const [ip, t] of Object.entries(this.state.trusted)) if (now - t > 30 * DAY) delete this.state.trusted[ip];
    this.state.events = this.state.events.slice(0, 300);
    try {
      const tmp = this.file() + ".tmp";
      writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
      renameSync(tmp, this.file());
      this.dirty = false;
    } catch (e) { this.log("shield: save failed", e.message); }
  }

  // ---------------------------------------------------------------- feeds
  feedFile(f) { return join(this.dir, "feeds", f.id + ".txt"); }
  loadFeed(f, text) {
    try {
      if (text === undefined) { if (!existsSync(this.feedFile(f))) return false; text = readFileSync(this.feedFile(f), "utf8"); }
      const sets = parseFeed(f, text);
      const count = Object.values(sets).reduce((a, s) => a + s.count, 0);
      if (!count) throw new Error("no addresses in it");
      this.lists.set(f.id, sets);
      this.state.feeds[f.id] = { ...this.state.feeds[f.id], count, loaded: Date.now() };
      return true;
    } catch (e) { this.state.feeds[f.id] = { ...this.state.feeds[f.id], error: e.message }; return false; }
  }
  async refreshFeed(f) {
    const meta = (this.state.feeds[f.id] ||= {});
    meta.tried = Date.now();
    try {
      const r = await this.fetch(f.url, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(f.timeout || 30000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      if (!this.loadFeed(f, text)) throw new Error(meta.error || "couldn't read it");
      writeFileSync(this.feedFile(f), text);
      meta.at = Date.now(); delete meta.error;
    } catch (e) {
      meta.error = e.message || String(e);
      this.log(`shield: ${f.name}: ${meta.error}`);
    }
    this.dirty = true;
  }
  async refreshDue(force) {
    for (const f of FEEDS) {
      const meta = this.state.feeds[f.id] || {};
      let at = meta.at || 0;
      if (!at) try { at = statSync(this.feedFile(f)).mtimeMs; } catch { /* never fetched */ }
      const retry = meta.error && Date.now() - (meta.tried || 0) > 30 * 60e3;
      if (force || Date.now() - at > f.every || (!this.lists.has(f.id) && (retry || !meta.tried))) await this.refreshFeed(f);
    }
  }

  // Every list that names this address: [{id, name, strength, extra?}]. Synchronous, microseconds.
  lookup(ip) {
    ip = normIp(ip);
    if (!isIP(ip) || isPrivate(ip)) return [];
    const out = [];
    for (const f of FEEDS) {
      const sets = this.lists.get(f.id);
      if (!sets) continue;
      for (const strength of ["strong", "weak", "info"]) {
        const hit = sets[strength]?.has(ip);
        if (hit) { out.push({ id: f.id, name: f.name, strength, ...(hit !== true ? { extra: hit } : {}) }); break; }
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- who is exempt
  trust(ip) {
    ip = normIp(ip);
    if (!isIP(ip) || isPrivate(ip)) return;
    const was = this.state.trusted[ip];
    this.state.trusted[ip] = Date.now();
    if (!was || Date.now() - was > HOUR) this.dirty = true;
    const b = this.state.bans[ip];
    if (b) { delete this.state.bans[ip]; this.event(ip, "lifted", "it signed in to Aegis", {}); }
  }
  isTrusted(ip) { const t = this.state.trusted[ip]; return !!t && Date.now() - t < 30 * DAY; }

  // ---------------------------------------------------------------- the check
  // info: {method, path, host, country, ua, trusted: () => bool (a valid session)}
  // -> null (let it through) or {status, body, why}
  gate(rawIp, info = {}) {
    const ip = normIp(rawIp);
    if (!isIP(ip) || isPrivate(ip) || this.state.allow[ip]) return null;
    let tr = null;
    const trusted = () => {
      if (tr === null) tr = this.isTrusted(ip) || !!info.trusted?.();
      if (tr) this.trust(ip);
      return tr;
    };
    const now = Date.now();
    const ban = this.state.bans[ip];
    if (ban && (!ban.until || ban.until > now)) {
      if (ban.source !== "manual" && trusted()) return null;           // trust() lifted it
      ban.hits = (ban.hits || 0) + 1; ban.last = now;
      this.state.stats.blocked++; this.dirty = true;
      this.event(ip, "blocked", ban.reason, info, 600e3);
      return { status: 403, body: "Blocked.", why: ban.reason };
    }
    const s = this.settings;
    const probe = classify(info.path);
    const lists = this.lookup(ip);
    if (!s.auto) {
      if (probe === 3 && s.drop && !trusted()) return this.drop(ip, info);
      return null;
    }
    const strong = lists.filter((l) => l.strength === "strong");
    if (strong.length && !trusted()) {
      return this.ban(ip, `on ${strong.map((l) => l.name).join(", ")}`, { source: "list", ttl: 7 * DAY, info });
    }
    if (probe) {
      if (trusted()) return null;
      const sc = this.scores.get(ip) || { score: 0, probes: 0, paths: [], first: now, last: now };
      if (now - sc.last > DAY) { sc.score = 0; sc.probes = 0; sc.paths = []; }
      sc.score += probe; sc.probes++; sc.last = now;
      sc.paths.unshift(String(info.path).slice(0, 120)); sc.paths.length = Math.min(sc.paths.length, 8);
      this.scores.set(ip, sc);
      if (this.scores.size > 20000) this.scores.delete(this.scores.keys().next().value);
      const marks = this.marks(ip, lists);
      if (marks.length || sc.score >= 6) {
        const why = marks.length ? `${probe === 3 ? "sent payloads" : "probed"} (${info.path}) and ${marks.join(", ")}`
                                 : `sent ${sc.probes} payloads (${sc.paths.slice(0, 2).join(", ")})`;
        return this.ban(ip, why, { source: "payload", ttl: 30 * DAY, info });
      }
      this.enqueue(ip, { probe: true });
      if (probe === 3 && s.drop) return this.drop(ip, info);
      this.event(ip, "probe", `asked for ${String(info.path).slice(0, 80)}`, info, 60e3);
      return null;
    }
    // first sight: yours (a session) is never looked up, so never banned for what a shared address did
    if (this.due(ip, false) && !trusted()) this.enqueue(ip, {});
    return null;
  }
  drop(ip, info) {
    this.state.stats.dropped++; this.dirty = true;
    this.event(ip, "dropped", "a payload: never reached the app", info, 10e3);
    return { status: 404, body: "Not found", why: "payload" };
  }
  // what else is against an address: weaker lists, Tor, and what the lookups said
  marks(ip, lists = this.lookup(ip)) {
    const out = lists.filter((l) => l.strength !== "strong").map((l) => (l.id === "tor" ? "is a Tor exit" : `is on ${l.name}`));
    const v = this.verdicts.get(ip);
    if (v?.bad) out.push(...v.why.slice(0, 2));
    return out;
  }

  ban(ip, reason, { source = "manual", ttl = 0, info = {} } = {}) {
    ip = normIp(ip);
    if (!isIP(ip)) throw new Error("That isn't an IP address.");
    const now = Date.now();
    const b = { at: now, until: ttl ? now + ttl : null, reason: String(reason).slice(0, 300), source, hits: 1, last: now,
                country: info.country || this.state.bans[ip]?.country || "", host: info.host || "" };
    this.state.bans[ip] = b;
    this.state.stats.banned++; this.dirty = true;
    this.event(ip, "banned", b.reason, info);
    this.log("shield: banned", ip, "-", b.reason);
    try { this.onBan?.(ip, b); } catch { /* best effort */ }
    if (Object.keys(this.state.bans).length > 50000) {
      const oldest = Object.entries(this.state.bans).sort((a, c) => a[1].last - c[1].last)[0];
      delete this.state.bans[oldest[0]];
    }
    return { status: 403, body: "Blocked.", why: b.reason };
  }
  unban(ip) {
    ip = normIp(ip);
    const had = !!this.state.bans[ip];
    delete this.state.bans[ip];
    this.scores.delete(ip); this.verdicts.delete(ip);
    if (had) { this.event(ip, "unbanned", "by you", {}); this.dirty = true; }
    return had;
  }
  allow(ip, on = true, note = "") {
    ip = normIp(ip);
    if (!isIP(ip)) throw new Error("That isn't an IP address.");
    if (on) { this.state.allow[ip] = { at: Date.now(), note: String(note).slice(0, 80) }; this.unban(ip); }
    else delete this.state.allow[ip];
    this.dirty = true;
  }

  event(ip, act, why, info = {}, quietMs = 0) {
    if (quietMs) {
      const k = `${ip}|${act}`, last = this.quiet.get(k) || 0;
      if (Date.now() - last < quietMs) return;
      this.quiet.set(k, Date.now());
      if (this.quiet.size > 10000) this.quiet.clear();
    }
    this.state.events.unshift({ t: Date.now(), ip, act, why: String(why || "").slice(0, 300), host: info.host || "",
                                path: info.path ? String(info.path).slice(0, 160) : "", method: info.method || "", country: info.country || "" });
    if (this.state.events.length > 400) this.state.events.length = 300;
    this.dirty = true;
  }

  // ---------------------------------------------------------------- lookups (in the background)
  due(ip, probe) {
    if (!this.remote || !this.settings.lookups) return false;
    const last = this.queued.get(ip);
    return !(last && Date.now() - last.at < 6 * HOUR && (last.probe || !probe));
  }
  enqueue(ip, { probe }) {
    if (!this.due(ip, probe)) return;
    this.queued.set(ip, { at: Date.now(), probe: !!probe });
    if (this.queued.size > 20000) this.queued.delete(this.queued.keys().next().value);
    if (this.queue.length > 500) return;          // a flood: the lists still apply
    this.queue.push({ ip, probe });
    this.pump();
  }
  pump() {
    while (this.running < 4 && this.queue.length) {
      const { ip, probe } = this.queue.shift();
      this.running++;
      this.remote(ip, { probe }).then((r) => this.judge(ip, r)).catch(() => {})
        .finally(() => { this.running--; this.pump(); });
    }
  }
  // a lookup's answer. Banned on its own only for a hard sign (GreyNoise has seen
  // it attack, DroneBL lists it, or a strong list): Spamhaus's XBL also names
  // school and carrier NATs with one infected device behind them, so that (and
  // anything else bad) bans only together with a probe.
  judge(ip, r) {
    if (!r?.verdict) return;
    this.state.stats.checked++; this.dirty = true;
    const level = r.verdict.level;
    const bad = level === "malicious" || level === "suspicious";
    this.verdicts.set(ip, { at: Date.now(), level, why: r.verdict.why, bad });
    if (this.verdicts.size > 20000) this.verdicts.delete(this.verdicts.keys().next().value);
    if (!this.settings.auto || this.state.allow[ip] || this.state.bans[ip] || this.isTrusted(ip)) return;
    const sc = this.scores.get(ip);
    const src = r.sources || {};
    const hard = [];
    if (src.greynoise?.result?.classification === "malicious") hard.push("GreyNoise has seen it attack");
    if (src.dnsbl?.result?.dronebl?.listed) hard.push(`DroneBL: ${src.dnsbl.result.dronebl.why.join(", ")}`);
    if (!r.sources && level === "malicious") hard.push(...r.verdict.why.slice(0, 2));
    if (hard.length) this.ban(ip, hard.join(", "), { source: "lookup", ttl: 7 * DAY });
    else if (sc?.probes && (bad || level === "notice")) {
      this.ban(ip, `probed (${sc.paths[0]}) and ${r.verdict.why.slice(0, 2).join(", ")}`, { source: "payload", ttl: 30 * DAY });
    }
  }

  // ---------------------------------------------------------------- views
  // a client row's badge: banned, the lists that name it, its probes
  peek(ip) {
    ip = normIp(ip);
    if (!isIP(ip) || isPrivate(ip)) return null;
    const b = this.state.bans[ip], sc = this.scores.get(ip), v = this.verdicts.get(ip);
    return { banned: b && (!b.until || b.until > Date.now()) ? { reason: b.reason, at: b.at, until: b.until, source: b.source } : null,
             allowed: !!this.state.allow[ip], trusted: this.isTrusted(ip),
             lists: this.lookup(ip).map(({ id, name, strength }) => ({ id, name, strength })),
             probes: sc?.probes || 0, verdict: v ? v.level : null };
  }
  view() {
    const now = Date.now();
    const bans = Object.entries(this.state.bans).filter(([, b]) => !b.until || b.until > now)
      .map(([ip, b]) => ({ ip, ...b })).sort((a, b) => b.last - a.last);
    return {
      settings: this.settings, stats: { ...this.state.stats, bans: bans.length },
      feeds: FEEDS.map((f) => ({ id: f.id, name: f.name, about: f.about, strength: f.strength, url: f.url, every: f.every,
                                 ...(this.state.feeds[f.id] || {}), loadedNow: this.lists.has(f.id) })),
      bans: bans.slice(0, 500), allow: Object.entries(this.state.allow).map(([ip, a]) => ({ ip, ...a })),
      trusted: Object.entries(this.state.trusted).map(([ip, at]) => ({ ip, at })).sort((a, b) => b.at - a.at).slice(0, 50),
      probing: [...this.scores.entries()].filter(([ip]) => !this.state.bans[ip]).map(([ip, s]) => ({ ip, ...s }))
        .sort((a, b) => b.last - a.last).slice(0, 50),
      events: this.state.events.slice(0, 200), queue: this.queue.length,
    };
  }
  setSettings(patch) {
    for (const k of ["auto", "drop", "lookups"]) if (typeof patch[k] === "boolean") this.settings[k] = patch[k];
    this.dirty = true;
    return this.settings;
  }
}
