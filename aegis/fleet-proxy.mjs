// ssh -o ProxyCommand="node fleet-proxy.mjs <socket> <machine id>": joins
// ssh's stdin/stdout to a stream through that machine's agent
// (aegis/fleet-agent.mjs). Exits when either side closes.
import { connect } from "node:net";

const [sock, id] = process.argv.slice(2);
if (!sock || !/^m-[0-9a-f]{10}$/.test(id || "")) { process.stderr.write("usage: fleet-proxy.mjs <socket> <machine id>\n"); process.exit(2); }
const c = connect(sock, () => { c.write(`${id}\n`); process.stdin.pipe(c); c.pipe(process.stdout); });
c.on("error", (e) => { process.stderr.write(`aegis: the agent link is not there (${e.code || e.message})\n`); process.exit(255); });
c.on("close", () => process.exit(0));
process.stdin.on("end", () => c.end());
