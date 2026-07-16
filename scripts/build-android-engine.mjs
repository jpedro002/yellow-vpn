// Build vpn-engine as a `libvpn_engine.so` per Android ABI and stage it into the
// APK's jniLibs so the Kotlin `VpnService` can `System.loadLibrary("vpn_engine")`.
//
// Requires the Android NDK and `cargo-ndk` (cargo install cargo-ndk). The NDK is
// located via ANDROID_NDK_HOME, or the newest NDK under $ANDROID_HOME/ndk.
//
// Usage: node scripts/build-android-engine.mjs [--release]
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const release = process.argv.includes("--release");

// A1 targets: arm64 devices + x86_64 emulator. Add armeabi-v7a / x86 in A4.
const abis = ["arm64-v8a", "x86_64"];
const jniLibs = join(
  root, "src-tauri", "gen", "android", "app", "src", "main", "jniLibs",
);

// Resolve the NDK so cargo-ndk can find it (it also honors ANDROID_NDK_HOME).
function resolveNdk() {
  if (process.env.ANDROID_NDK_HOME) return process.env.ANDROID_NDK_HOME;
  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT;
  if (sdk) {
    const ndkRoot = join(sdk, "ndk");
    if (existsSync(ndkRoot)) {
      const versions = readdirSync(ndkRoot).sort();
      if (versions.length) return join(ndkRoot, versions[versions.length - 1]);
    }
  }
  return null;
}

const ndk = resolveNdk();
if (!ndk) {
  console.error(
    "Android NDK not found. Set ANDROID_NDK_HOME or install the NDK via the SDK manager.",
  );
  process.exit(1);
}

const env = { ...process.env, ANDROID_NDK_HOME: ndk };

// cargo ndk -t <abi> -t <abi> -o <jniLibs> build -p vpn-engine [--release]
const args = [];
for (const abi of abis) args.push("-t", abi);
args.push("-o", jniLibs, "build", "-p", "vpn-engine");
if (release) args.push("--release");

try {
  execFileSync("cargo", ["ndk", ...args], { stdio: "inherit", cwd: root, env });
} catch (e) {
  console.error(
    "cargo-ndk failed. Install it with `cargo install cargo-ndk` and ensure the " +
      "Android targets are added (rustup target add aarch64-linux-android x86_64-linux-android).",
  );
  process.exit(1);
}

console.log(`staged libvpn_engine.so for [${abis.join(", ")}] into ${jniLibs}`);
