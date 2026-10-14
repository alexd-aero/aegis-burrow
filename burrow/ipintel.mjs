// Who is this client? An IP's reputation, with a verdict on top, in well under
// half a second: the slow part (big lists) is already in memory, and whatever
// the network hasn't answered by the deadline is filled in when it does.
//
//   lists      the shield's blocklists (shield.mjs: FireHOL, blocklist.de, CINS,
//              Emerging Threats, IPsum, the elsnet ban list from vonweber.nl,
//              Tor exits), downloaded every few hours and looked up locally.
//   greynoise  GreyNoise Community: is it an internet-wide scanner, and is it
//              known to be malicious (or a known-good service, "riot")?
//   shodan     Shodan InternetDB: its open ports, known vulnerabilities, tags.
//   sfs        StopForumSpam: how often it was reported for spam and abuse.
//   dnsbl      Spamhaus ZEN, DroneBL and SpamCop, asked over DNS.
//   tor        the Tor exit list (from the shield's copy, or TorDNSEL over DNS).
//   owner      ipinfo.io: who holds the address (network, country, host name).
//
// checkIp answers by its deadline (450 ms) with what it has; the rest is marked
// `pending` and lands in the cache (30 minutes) as it arrives, so asking again a
// moment later gives the whole picture.

import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";

const UA = "Mozilla/5.0 (aegis-burrow ip check)";
const TTL_MS = 30 * 60e3;
const DEADLINE_MS = 450;
const cache = new Map();          // ip -> {at, result} (whole answers only)
const inflight = new Map();       // ip -> Promise of the whole answer
let local = null;                 // (ip) -> [{id, name, strength, extra?}]: the shield's lists
let localTor = null;              // (ip) -> true | false | null (no list yet)
export function useLists(lookup, tor) { local = lookup; localTor = tor || null; }
const resolver = new Resolver({ timeout: 4000, tries: 1 });

const json = async (url, ms = 8000) => {
  const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/json" }, signal: AbortSignal.timeout(ms) });
  if (r.status === 404) return null;
  if (r.status === 429) throw new Error("rate-limited, try later");
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
};
const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.)/.test(ip) || /^(::1|f[cd]|fe80)/i.test(ip);
const reverse4 = (ip) => ip.split(".").reverse().join(".");

// ------------------------------------------------------------------ the sources
// What vonweber.nl's page says about one IP: listed (with its host name, since when, how
// many times) or not. `total` is how many entries the page showed (with ?ip= it
// shows the part of the list around that address). `page` is its HTML.
export function parseVonweber(page, ip) {
  const text = page.replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ");
  const total = Number((/(\d+)\s+blacklisted\s+hosts and\s+IPs/i.exec(text) || [])[1]) || null;
  const esc = ip.replace(/[.:]/g, (c) => "\\" + c);
  const m = new RegExp(`(?:^|\\s)(\\S+)\\s+${esc}\\s+(\\d{4}/\\d{2}/\\d{2})-(\\d{2}:\\d{2}:\\d{2})\\s+(\\d+)(?=\\s)`).exec(text);
  if (!total && !m) throw new Error("the page didn't look like the list");
  return m ? { listed: true, host: m[1] === "-" ? null : m[1], since: `${m[2].replace(/\//g, "-")} ${m[3]}`, hits: Number(m[4]), total }
           : { listed: false, total };
}
// GreyNoise's free tier has a daily allowance: once it says no, rest a while
let greynoiseRest = 0;
async function greynoise(ip) {
  if (Date.now() < greynoiseRest) throw new Error("rate-limited, resting for now");
  let j;
  try { j = await json(`https://api.greynoise.io/v3/community/${ip}`); }
  catch (e) { if (/rate-limited/.test(e.message)) greynoiseRest = Date.now() + 30 * 60e3; throw e; }
  if (!j || j.noise === undefined) return { seen: false };
  return { seen: true, scanner: !!j.noise, benign: !!j.riot, classification: j.classification || null, name: j.name && j.name !== "unknown" ? j.name : null, lastSeen: j.last_seen || null };
}
async function shodan(ip) {
  const j = await json(`https://internetdb.shodan.io/${ip}`);
  if (!j) return { seen: false };
  return { seen: true, ports: (j.ports || []).slice(0, 20), vulns: (j.vulns || []).length, tags: j.tags || [], hostnames: (j.hostnames || []).slice(0, 3) };
}
async function sfs(ip) {
  const j = await json(`https://api.stopforumspam.org/api?ip=${ip}&json`);
  const x = j?.ip || {};
  return { reports: Number(x.frequency) || 0, lastSeen: x.lastseen || null, confidence: x.confidence ? Number(x.confidence) : null };
}
// The DNS blocklists (IPv4 only). 127.255.255.x from Spamhaus means it won't
// answer this resolver, which is not a listing.
const DNSBLS = [
  { id: "spamhaus", zone: "zen.spamhaus.org", what: { "127.0.0.2": "spam source", "127.0.0.3": "spam source", "127.0.0.4": "infected / exploited", "127.0.0.9": "hijacked network" },
    // the PBL: home and mobile ranges that shouldn't send mail themselves. Every
    // ordinary visitor is on it, so for a web server it says nothing.
    ignore: ["127.0.0.10", "127.0.0.11"] },
  { id: "dronebl", zone: "dnsbl.dronebl.org", what: { "127.0.0.3": "IRC drone", "127.0.0.5": "bottler", "127.0.0.6": "unknown spambot or drone", "127.0.0.7": "DDoS drone", "127.0.0.8": "SOCKS proxy", "127.0.0.9": "HTTP proxy", "127.0.0.10": "proxy chain", "127.0.0.11": "web page proxy", "127.0.0.13": "brute-force attacker", "127.0.0.14": "open Wingate", "127.0.0.15": "compromised router", "127.0.0.16": "autorooting worm", "127.0.0.17": "botnet" } },
  { id: "spamcop", zone: "bl.spamcop.net", what: { "127.0.0.2": "spam source" } },
];
async function dnsbl(ip) {
  if (isIP(ip) !== 4) return { skipped: "IPv6" };
  const out = {};
  await Promise.all(DNSBLS.map(async (b) => {
    try {
      const a = await resolver.resolve4(`${reverse4(ip)}.${b.zone}`);
      if (a.some((x) => x.startsWith("127.255.255."))) { out[b.id] = { error: "refused this resolver" }; return; }
      const real = a.filter((x) => !(b.ignore || []).includes(x));
      out[b.id] = real.length ? { listed: true, why: [...new Set(real.map((x) => b.what[x] || x))] } : { listed: false, note: "home or mobile range (PBL)" };
    } catch (e) { out[b.id] = e.code === "ENOTFOUND" || e.code === "ENODATA" ? { listed: false } : { error: e.code || e.message }; }
  }));
  return out;
}
async function tor(ip) {
  const known = localTor?.(ip);
  if (known === true || known === false) return { exit: known };
  if (isIP(ip) !== 4) return { skipped: "IPv6" };
  try { const a = await resolver.resolve4(`${reverse4(ip)}.dnsel.torproject.org`); return { exit: a.includes("127.0.0.2") }; }
  catch (e) { return e.code === "ENOTFOUND" || e.code === "ENODATA" ? { exit: false } : { error: e.code || e.message }; }
}
async function owner(ip) {
  const j = await json(`https://ipinfo.io/${ip}/json`);
  return j ? { org: j.org || null, country: j.country || null, city: j.city || null, hostname: j.hostname || null } : null;
}

// ------------------------------------------------------------------ the verdict
function verdict(r) {
  const why = [];
  let level = "clean";
  const up = (l) => { const order = ["clean", "notice", "suspicious", "malicious"]; if (order.indexOf(l) > order.indexOf(level)) level = l; };
  const g = r.sources.greynoise?.result;
  if (g?.classification === "malicious") { up("malicious"); why.push("GreyNoise: known malicious"); }
  else if (g?.scanner) { up("suspicious"); why.push(`mass scanner${g.name ? ` (${g.name})` : ""}`); }
  if (g?.benign) why.push(`known service${g.name ? `: ${g.name}` : ""}`);
  const d = r.sources.dnsbl?.result || {};
  for (const [id, x] of Object.entries(d)) if (x?.listed) { up(id === "spamcop" ? "suspicious" : "malicious"); why.push(`${id}: ${x.why.join(", ")}`); }
  const L = r.sources.lists?.result?.hits || [];
  for (const l of L) {
    if (l.id === "tor") continue;
    if (l.strength === "strong") { up("malicious"); why.push(`on ${l.name}`); }
    else { up("suspicious"); why.push(l.id === "elsnet" && l.extra?.since ? `banned by elsnet since ${l.extra.since.slice(0, 10)}` : `on ${l.name}`); }
  }
  const s = r.sources.sfs?.result;
  if (s?.reports > 0) { up(s.reports > 5 ? "suspicious" : "notice"); why.push(`${s.reports} spam report${s.reports === 1 ? "" : "s"}`); }
  if (r.sources.tor?.result?.exit) { up("notice"); why.push("Tor exit node"); }
  const sh = r.sources.shodan?.result;
  if (sh?.vulns) { up("notice"); why.push(`${sh.vulns} known vulnerabilit${sh.vulns === 1 ? "y" : "ies"} on its own services`); }
  if (sh?.tags?.length) why.push(sh.tags.join(", "));
  return { level, why };
}

function localLists(ip) {
  if (!local) throw new Error("the lists are still downloading");
  return { hits: local(ip) };
}

// Check one IP. light: only what decides a ban (the shield's background lookups:
// lists, DNS blocklists, StopForumSpam, and GreyNoise when it probed).
export async function checkIp(ip, { fresh = false, deadline = DEADLINE_MS, light = false, probe = false } = {}) {
  ip = String(ip || "").trim().replace(/^::ffff:/, "");
  if (!isIP(ip)) throw new Error("That isn't an IP address.");
  if (isPrivate(ip)) return { ip, private: true, verdict: { level: "clean", why: ["a private or local address: yours"] }, sources: {}, at: Date.now() };
  const hit = cache.get(ip);
  const enough = (full, hasGn) => (light ? !probe || hasGn : full);
  if (!fresh && hit && Date.now() - hit.at < TTL_MS && enough(hit.result.full, "greynoise" in hit.result.sources)) return hit.result;
  let job = inflight.get(ip);
  if (fresh || !job || !enough(job.full, job.gn)) job = start(ip, light, probe);
  if (!deadline) return job.whole;
  let timer;
  await Promise.race([job.whole, new Promise((res) => { timer = setTimeout(res, deadline); })]);
  clearTimeout(timer);
  return job.build();
}
function start(ip, light, probe) {
  const run = async (fn) => { try { return { result: await fn() }; } catch (e) { return { error: e.message || String(e) }; } };
  const sources = { lists: run(async () => localLists(ip)), dnsbl: run(() => dnsbl(ip)), sfs: run(() => sfs(ip)) };
  if (!light || probe) sources.greynoise = run(() => greynoise(ip));
  if (!light) Object.assign(sources, { shodan: run(() => shodan(ip)), tor: run(() => tor(ip)), owner: run(() => owner(ip)) });
  const got = {};
  const build = () => {
    const { owner: o, ...rest } = got;
    const result = { ip, at: Date.now(), owner: o?.result || null, sources: rest, full: !light,
                     pending: Object.keys(sources).filter((k) => !(k in got)) };
    if (!result.pending.length) delete result.pending;
    result.verdict = verdict(result);
    return result;
  };
  const job = { full: !light, gn: "greynoise" in sources, build };
  job.whole = Promise.all(Object.entries(sources).map(([k, p]) => p.then((r) => { got[k] = r; }))).then(() => {
    const r = build();
    if (!light || !cache.get(ip)?.result?.full) cache.set(ip, { at: Date.now(), result: r });   // never a light one over a whole one
    if (cache.size > 5000) cache.delete(cache.keys().next().value);
    if (inflight.get(ip) === job) inflight.delete(ip);
    return r;
  });
  inflight.set(ip, job);
  return job;
}

// Check many (a tunnel's clients): all at once, each by its own deadline.
export async function checkMany(ips, { limit = 60 } = {}) {
  const list = [...new Set(ips.map((x) => String(x).replace(/^::ffff:/, "")))].filter((x) => isIP(x)).slice(0, limit);
  const out = {};
  await Promise.all(list.map(async (ip) => { out[ip] = await checkIp(ip).catch((e) => ({ ip, error: e.message })); }));
  return out;
}
