// The command line's half of an addon job run in your own terminal
// (`aegis addons install ID`, when Aegis can't get root itself, or with --here).
//
// Aegis makes the job as always and hands its script step over once, on the
// control socket (POST /addons/<id>/runspec). This runs `bash script` here, as
// you, with this terminal as its stdin: a plain `sudo` in it asks for your
// password right here. Every line goes to the screen and back to Aegis (POST
// /addons/jobs/<job>/line, batched), so the dashboard shows the job live, and
// the exit code ends it (…/done): Aegis then finishes it exactly as if it had
// run the script itself (installed, version, the update swapped in, …).
// Ctrl-C stops the script, not this: the code still goes back. Cancel in the
// dashboard stops the script here too.

import { spawn as nodeSpawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";

// The script and everything it started (it stays in this terminal's process
// group, so sudo can still ask on the terminal: no killing by group).
export function killTree(pid, sig = "SIGTERM") {
  const parent = new Map();
  try {
    for (const d of readdirSync("/proc")) {
      if (!/^\d+$/.test(d)) continue;
      try { const st = readFileSync(`/proc/${d}/stat`, "utf8"); parent.set(Number(d), Number(st.slice(st.lastIndexOf(")") + 2).split(" ")[1])); } catch { /* gone */ }
    }
  } catch { /* no /proc */ }
  const all = [pid];
  for (let i = 0; i < all.length; i++) for (const [p, pp] of parent) if (pp === all[i]) all.push(p);
  for (const p of all.reverse()) { try { process.kill(p, sig); } catch { /* gone */ } }
}

const id = (s) => s;
// call(method, path, body, timeout) -> parsed JSON, throws Error{status} on HTTP errors
export async function runHere({ call, op, id: aid, body = {}, spawn = nodeSpawn, stdin = "inherit",
                                print = (s) => process.stdout.write(s + "\n"), raw = (s) => process.stderr.write(s),
                                c = { dim: id, yellow: id, red: id, green: id }, flushMs = 300, pollMs = 800 }) {
  const spec = await call("POST", `/addons/${aid}/runspec`, { ...body, op }, 15 * 60e3);
  const job = spec.job.id;
  const follow = async () => {
    for (;;) {
      const j = await call("GET", `/addons/jobs/${job}`);
      if (j.state !== "running") return j;
      await new Promise((r) => setTimeout(r, pollMs));
    }
  };
  if (spec.done) return { job: await follow(), ran: false };

  const env = { ...process.env, ...spec.env };
  for (const k of ["SUDO_ASKPASS", "ADDON_ASKPASS_TOKEN", "FORGE_ADDON_ASKPASS_TOKEN"]) delete env[k];
  print(c.dim(`  running ${spec.script} here, as you (sudo in it asks in this terminal)`));
  let queue = [], stopped = null, chain = Promise.resolve(), sent = Date.now();
  const flush = (beat = false) => {
    // nothing to say for a while: an empty batch, so a cancel in the dashboard is heard here
    if (!queue.length && beat && Date.now() - sent > 2000) queue.push(null);
    while (queue.length) {
      sent = Date.now();
      let size = 0, n = 0;
      while (n < queue.length && n < 400 && size < 30000) size += (queue[n++]?.length || 0) + 8;
      const batch = queue.splice(0, n).filter((l) => l !== null);
      chain = chain.then(() => (stopped ? null : call("POST", `/addons/jobs/${job}/line`, { token: spec.token, lines: batch }).catch((e) => {
        if (e.status === 410 || e.status === 403) { stopped = e.message; killTree(child.pid); }
      })));
    }
    return chain;
  };
  const show = (line) => {
    if (!line.startsWith("::")) return print(line);
    const [word, ...rest] = line.slice(2).split(" "), arg = rest.join(" ").trim();
    if (word === "progress") { const [pct, ...label] = arg.split(" "); print(c.dim(`  · ${pct}%${label.length ? " " + label.join(" ") : ""}`)); }
    else if (word === "phase") print(c.dim(`  · ${arg}`));
    else if (word === "warn") print(c.yellow(`  ! ${arg}`));
    else if (word === "open") print(c.dim(`  open: ${arg}`));
  };
  const splitter = (onLine) => {
    let buf = "";
    return { feed: (chunk) => { buf += chunk; let i; while ((i = buf.indexOf("\n")) >= 0) { const l = buf.slice(0, i).replace(/\r$/, ""); buf = buf.slice(i + 1); onLine(l); } },
             end: () => { if (buf) { onLine(buf); buf = ""; } } };
  };
  const child = spawn("bash", [spec.script], { cwd: spec.cwd, env, stdio: [stdin, "pipe", "pipe"] });
  const so = splitter((l) => { show(l); queue.push(l); });
  const se = splitter((l) => { queue.push(l); });
  child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
  child.stdout.on("data", so.feed);
  child.stderr.on("data", (d) => { raw(d); se.feed(d); });             // as it comes: a prompt has no newline yet
  const timer = setInterval(() => flush(true), flushMs);
  const ignore = () => {};                                             // Ctrl-C is the script's; this reports what became of it
  process.on("SIGINT", ignore);
  const code = await new Promise((resolve) => {
    const codeOf = (cd, sig) => cd ?? (sig ? 128 + ({ SIGINT: 2, SIGTERM: 15, SIGKILL: 9 }[sig] || 1) : 1);
    child.on("error", (e) => { queue.push(`couldn't start bash: ${e.message}`); resolve(127); });
    child.on("close", (cd, sig) => resolve(codeOf(cd, sig)));
    // something it left running may hold its output open: a moment for the last lines, then on
    child.on("exit", (cd, sig) => setTimeout(() => resolve(codeOf(cd, sig)), 1500).unref?.());
  });
  process.off("SIGINT", ignore);
  clearInterval(timer);
  so.end(); se.end();
  await flush();
  if (stopped) { print(c.red(`  ✗ ${stopped}`)); return { job: await follow(), ran: true, code, stopped }; }
  await call("POST", `/addons/jobs/${job}/done`, { token: spec.token, code });
  return { job: await follow(), ran: true, code };
}
