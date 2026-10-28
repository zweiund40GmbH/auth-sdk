// Checks the npm package content (`npm pack --dry-run --json`): exactly the build output, README,
// licenses and package.json – no sources, tests or stray files.
import { execFileSync } from "node:child_process";

// `prepack` copies the licenses; its output may precede the JSON, which starts at a line with "[".
const out = execFileSync("npm", ["pack", "--dry-run", "--json"], { encoding: "utf8" });
const files = JSON.parse(out.slice(out.search(/^\[/m)))[0].files.map((f) => f.path).sort();
const required = ["LICENSE-APACHE", "LICENSE-MIT", "README.md", "package.json", "dist/index.js", "dist/index.d.ts"];
const allowed = (p) => required.includes(p) || /^dist\/[a-z-]+\.(js|d\.ts)$/.test(p);
const missing = required.filter((r) => !files.includes(r));
const unexpected = files.filter((f) => !allowed(f));
if (missing.length > 0 || unexpected.length > 0) {
  console.error(`npm package content wrong. missing: ${missing.join(", ") || "-"}; unexpected: ${unexpected.join(", ") || "-"}`);
  process.exit(1);
}
console.log(`npm package ok: ${files.length} files`);
