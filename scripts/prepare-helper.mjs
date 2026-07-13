// Build the elevated VPN helper and stage it as a Tauri sidecar (externalBin).
//
// Tauri expects sidecar binaries named `<name>-<target-triple>` (with `.exe` on
// Windows) and places them next to the main executable in the bundle — which is
// exactly where the GUI's `helper_path()` looks for `yellow-vpn-helper` at
// runtime. Works on macOS, Linux, and Windows.
//
// Usage: node scripts/prepare-helper.mjs [--release]
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const release = process.argv.includes("--release");

// Host target triple, e.g. `aarch64-apple-darwin`.
const rustcOut = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
const triple = rustcOut.match(/^host:\s*(.+)$/m)?.[1]?.trim();
if (!triple) {
  console.error("could not determine host target triple from `rustc -vV`");
  process.exit(1);
}

const isWindows = triple.includes("windows");
const exeSuffix = isWindows ? ".exe" : "";
const profileDir = release ? "release" : "debug";

// Build the helper.
execFileSync(
  "cargo",
  ["build", "-p", "vpn-helper", ...(release ? ["--release"] : [])],
  { stdio: "inherit", cwd: root },
);

const src = join(root, "target", profileDir, `yellow-vpn-helper${exeSuffix}`);
const destDir = join(root, "src-tauri", "binaries");
const dest = join(destDir, `yellow-vpn-helper-${triple}${exeSuffix}`);

mkdirSync(destDir, { recursive: true });
copyFileSync(src, dest);
console.log(`staged sidecar: ${dest}`);
