// Rebuilds the vendored bundles. Only needed after changing client/ or
// upgrading noble, xml-crypto or xmldom; the repository ships the built files,
// so installs never run npm.
//
//   npm install && npm run build
//
//   public/login.js         the sign-in / first-run page (browser)
//   aegis/vendor/pq.mjs     X-Wing for the server (Node)
//   aegis/vendor/saml.mjs   XML signatures (xml-crypto) and an XML parser
//                           (@xmldom/xmldom) for SAML sign-in (aegis/sso.mjs)
import { build } from "esbuild";
import { readFileSync } from "node:fs";
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
// SAML: well-known libraries, not our own canonicalization. Their licenses
// (all MIT) ride at the top of the bundle; Node's builtins stay outside it.
const licenses = ["xml-crypto/LICENSE", "@xmldom/xmldom/LICENSE", "@xmldom/is-dom-node/LICENSE.md", "xpath/LICENSE"].map((f) => {
  const pkg = JSON.parse(readFileSync(join(root, "node_modules", f.split("/").slice(0, f.startsWith("@") ? 2 : 1).join("/"), "package.json"), "utf8"));
  return `/*! ${pkg.name} ${pkg.version}\n${readFileSync(join(root, "node_modules", f), "utf8").trim().replace(/\*\//g, "* /")}\n*/`;
}).join("\n");
await build({
  stdin: { contents: 'export { SignedXml } from "xml-crypto";\nexport { DOMParser, XMLSerializer } from "@xmldom/xmldom";', resolveDir: root },
  outfile: join(root, "aegis/vendor/saml.mjs"),
  bundle: true, minify: true, format: "esm", target: "node18", platform: "node", legalComments: "none",
  banner: { js: `// Built by client/build.mjs from xml-crypto and @xmldom/xmldom (MIT). Do not edit; run \`npm run build\`.\n${licenses}\n`
                + 'import { createRequire as __aegisRequire } from "node:module"; const require = __aegisRequire(import.meta.url);' },
});
console.log("built public/login.js, aegis/vendor/pq.mjs and aegis/vendor/saml.mjs");
