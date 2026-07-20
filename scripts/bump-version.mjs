// Bump the app version, synced across the four files that carry it:
//   package.json, src-tauri/tauri.conf.json, src-tauri/Cargo.toml and the
//   root Cargo.toml [workspace.package] (inherited by the engine/ipc/helper
//   crates and the Android .so).
//
// The tauri.conf.json version is the source of the Android versionCode
// (major*1e6 + minor*1e3 + patch) — it MUST always grow, otherwise Android
// refuses the upgrade over an already-installed build. This script enforces
// that the versionCode strictly increases.
//
// Usage: bun scripts/bump-version.mjs <patch|minor|major|x.y.z>
import { readFileSync, writeFileSync } from "node:fs";

const arg = process.argv[2];
if (!arg) {
  console.error("usage: bun scripts/bump-version.mjs <patch|minor|major|x.y.z>");
  process.exit(1);
}

const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const current = pkg.version;
const [major, minor, patch] = current.split(".").map(Number);

let next;
if (/^\d+\.\d+\.\d+$/.test(arg)) {
  next = arg;
} else if (arg === "major") {
  next = `${major + 1}.0.0`;
} else if (arg === "minor") {
  next = `${major}.${minor + 1}.0`;
} else if (arg === "patch") {
  next = `${major}.${minor}.${patch + 1}`;
} else {
  console.error(`invalid argument: ${arg}`);
  process.exit(1);
}

const [nMajor, nMinor, nPatch] = next.split(".").map(Number);
const code = (M, m, p) => M * 1_000_000 + m * 1_000 + p;
if (code(nMajor, nMinor, nPatch) <= code(major, minor, patch)) {
  console.error(
    `version ${next} does not grow the Android versionCode vs ${current} — the upgrade would be refused.`,
  );
  process.exit(1);
}

function bumpJson(path) {
  const json = JSON.parse(readFileSync(path, "utf8"));
  json.version = next;
  writeFileSync(path, JSON.stringify(json, null, 2) + "\n");
  console.log(`${path} -> ${next}`);
}

// Replace ONLY the package/workspace-level `version = "..."` (line-start;
// dependency versions live inside inline tables, not at column 0).
function bumpCargo(path) {
  const text = readFileSync(path, "utf8");
  const nextText = text.replace(/^version = "[^"]*"/m, `version = "${next}"`);
  if (nextText === text) {
    console.warn(`${path}: no package version line matched (skipped)`);
    return;
  }
  writeFileSync(path, nextText);
  console.log(`${path} -> ${next}`);
}

bumpJson("package.json");
bumpJson("src-tauri/tauri.conf.json");
bumpCargo("src-tauri/Cargo.toml");
bumpCargo("Cargo.toml");

console.log(`\nBumped ${current} -> ${next}. Next steps:\n`);
console.log(`  git commit -am "chore(release): v${next}"`);
console.log(`  git push origin HEAD`);
console.log(
  `\nDo NOT create the tag yourself. Pushing to master triggers`,
);
console.log(
  `.github/workflows/release.yml, which builds, publishes, and creates the v${next} tag.`,
);
