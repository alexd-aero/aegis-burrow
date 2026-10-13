// Who is this client? An IP's reputation, asked of several free sources at
// once (none needs an account or a key), with a verdict on top:
//
//   vonweber   vonweber.nl/cgi/blacklister.cgi: the hosts and IPs elsnet.org has
//              banned. Scraped live on every check (a 2.5 MB page; nothing
//              about it is kept here); one scan of a tunnel's clients reads it once.
//   greynoise  GreyNoise Community: is it an internet-wide scanner, and is it
//              known to be malicious (or a known-good service, "riot")?
//   shodan     Shodan InternetDB: its open ports, known vulnerabilities, tags.
//   sfs        StopForumSpam: how often it was reported for spam and abuse.
//   dnsbl      Spamhaus ZEN, DroneBL and SpamCop, asked over DNS.
//   tor        the Tor Project's exit list, asked over DNS (TorDNSEL).
//   owner      ipinfo.io: who holds the address (network, country, host name).
//
// Results are kept in memory for 30 minutes, so the page can ask again freely.

import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";

const UA = "Mozilla/5.0 (aegis-burrow ip check)";
const TTL_MS = 30 * 60e3;
const cache = new Map();          // ip -> {at, result}
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
// The elsnet.org ban list, read from vonweber.nl as it is right now.
export async function fetchVonweber(ip) {
  const r = await fetch(`https://vonweber.nl/cgi/blacklister.cgi?ip=${encodeURIComponent(ip)}`, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}
// What the page says about one IP: listed (with its host name, since when, how
// many times) or not, and how many entries the list has. `page` is its HTML.
export function parseVonweber(page, ip) {
  const text = page.replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ");
  const total = Number((/(\d+)\s+blacklisted\s+hosts and\s+IPs/i.exec(text) || [])[1]) || null;
  const esc = ip.replace(/[.:]/g, (c) => "\\" + c);
  const m = new RegExp(`(?:^|\\s)(\\S+)\\s+${esc}\\s+(\\d{4}/\\d{2}/\\d{2})-(\\d{2}:\\d{2}:\\d{2})\\s+(\\d+)(?=\\s)`).exec(text);
  if (!total && !m) throw new Error("the page didn't look like the list");
  return m ? { listed: true, host: m[1] === "-" ? null : m[1], since: `${m[2].replace(/\//g, "-")} ${m[3]}`, hits: Number(m[4]), total }
           : { listed: false, total };
}
async function greynoise(ip) {
  const j = await json(`https://api.greynoise.io/v3/community/${ip}`);
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
  { id: "spamhaus", zone: "zen.spamhaus.org", what: { "127.0.0.2": "spam source", "127.0.0.3": "spam source", "127.0.0.4": "infected / exploited", "127.0.0.9": "hijacked network", "127.0.0.10": "end-user range (shouldn't send mail)", "127.0.0.11": "end-user range (shouldn't send mail)" } },
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
      out[b.id] = { listed: true, why: [...new Set(a.map((x) => b.what[x] || x))] };
    } catch (e) { out[b.id] = e.code === "ENOTFOUND" || e.code === "ENODATA" ? { listed: false } : { error: e.code || e.message }; }
  }));
  return out;
}
async function tor(ip) {
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
  const v = r.sources.vonweber?.result;
  if (v?.listed) { up("suspicious"); why.push(`banned by elsnet since ${v.since.slice(0, 10)}`); }
  const s = r.sources.sfs?.result;
  if (s?.reports > 0) { up(s.reports > 5 ? "suspicious" : "notice"); why.push(`${s.reports} spam report${s.reports === 1 ? "" : "s"}`); }
  if (r.sources.tor?.result?.exit) { up("notice"); why.push("Tor exit node"); }
  const sh = r.sources.shodan?.result;
  if (sh?.vulns) { up("notice"); why.push(`${sh.vulns} known vulnerabilit${sh.vulns === 1 ? "y" : "ies"} on its own services`); }
  if (sh?.tags?.length) why.push(sh.tags.join(", "));
  return { level, why };
}

// Check one IP. vonweberPage: the page already scraped for this scan (or the promise of it).
export async function checkIp(ip, { vonweberPage = null, fresh = false } = {}) {
  ip = String(ip || "").trim().replace(/^::ffff:/, "");
  if (!isIP(ip)) throw new Error("That isn't an IP address.");
  if (isPrivate(ip)) return { ip, private: true, verdict: { level: "clean", why: ["a private or local address: yours"] }, sources: {}, at: Date.now() };
  const hit = cache.get(ip);
  if (!fresh && hit && Date.now() - hit.at < TTL_MS && !vonweberPage) return hit.result;
  const run = async (fn) => { try { return { result: await fn() }; } catch (e) { return { error: e.message || String(e) }; } };
  const [vonweber, greynoiseR, shodanR, sfsR, dnsblR, torR, ownerR] = await Promise.all([
    run(async () => parseVonweber(await (vonweberPage || fetchVonweber(ip)), ip)),
    run(() => greynoise(ip)), run(() => shodan(ip)), run(() => sfs(ip)), run(() => dnsbl(ip)), run(() => tor(ip)), run(() => owner(ip)),
  ]);
  const result = { ip, at: Date.now(), owner: ownerR.result || null,
                   sources: { vonweber, greynoise: greynoiseR, shodan: shodanR, sfs: sfsR, dnsbl: dnsblR, tor: torR } };
  result.verdict = verdict(result);
  cache.set(ip, { at: Date.now(), result });
  return result;
}

// Check many (a tunnel's clients): the elsnet list is scraped once for the scan.
export async function checkMany(ips, { limit = 60 } = {}) {
  const list = [...new Set(ips.map((x) => String(x).replace(/^::ffff:/, "")))].filter((x) => isIP(x)).slice(0, limit);
  const page = fetchVonweber(list.find((x) => !isPrivate(x)) || "1.1.1.1");
  page.catch(() => {});
  const out = {};
  for (let i = 0; i < list.length; i += 6) {
    const batch = list.slice(i, i + 6);
    const rs = await Promise.all(batch.map((ip) => checkIp(ip, { vonweberPage: page }).catch((e) => ({ ip, error: e.message }))));
    for (const r of rs) out[r.ip] = r;
  }
  return out;
}
