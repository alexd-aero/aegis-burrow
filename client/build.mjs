// Rebuilds the two vendored bundles. Only needed after changing client/ or
// upgrading noble; the repository ships the built files, so installs never
// run npm.
//
//   npm install && npm run build
//
//   public/login.js        the sign-in / first-run page (browser)
//   aegis/vendor/pq.mjs   X-Wing for the server (Node)
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const banner = { js: "// Built by client/build.mjs from @noble (MIT). Do not edit; run `npm run build`." };

await build({
  entryPoints: [join(root, "client/login-entry.js")], outfile: join(root, "public/login.js"),
  bundle: true, minify: true, format: "esm", target: "es2020", platform: "browser", banner, legalComments: "none",
});
await build({
  stdin: { contents: 'export { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";', resolveDir: root },
  outfile: join(root, "aegis/vendor/pq.mjs"),
  bundle: true, minify: true, format: "esm", target: "node18", platform: "node", banner, legalComments: "none",
});
console.log("built public/login.js and aegis/vendor/pq.mjs");
