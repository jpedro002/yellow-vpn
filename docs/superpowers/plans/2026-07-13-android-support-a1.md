# Android Support (A1: Porting Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get the Rust VPN engine running in-process on Android through a Tauri Kotlin plugin that hosts an `android.net.VpnService`, proving one protocol (AnyConnect) end-to-end with real traffic.

**Architecture:** The engine compiles as a `cdylib` `.so` for Android ABIs. A Tauri mobile plugin (Kotlin) subclasses `VpnService`, gets user consent, builds the tunnel (routes/DNS/MTU) with `VpnService.Builder`, `protect()`s the engine's outbound socket, and hands the pre-opened TUN file descriptor into the engine over JNI. On Android the engine skips `/dev/net/tun` (uses the passed fd) and skips OS route installation (the Builder does it).

**Tech Stack:** Rust (edition 2024, `tun` 0.7, tokio), the `jni` crate, Kotlin, Android `VpnService` + foreground service, Tauri v2 mobile plugin, Android NDK.

## Global Constraints

- Rust edition 2024, toolchain 1.88+ (workspace floor).
- The desktop build (linux/macos/windows) MUST stay green — all Android code is gated behind `#[cfg(target_os = "android")]` and an `android`-only crate-type; nothing here changes existing platform behaviour.
- MVP protocol is **AnyConnect** (`Protocol::AnyConnect`, the crate default). Checkpoint on Android is A2.
- Distribution is sideload/APK; no Google Play policy work in A1.
- The TUN fd is owned by the Kotlin `VpnService`; the engine borrows it for the connection and must NOT close it. (`tun` crate wraps it; ensure the wrapper does not own/close the fd — dup it on the Rust side if the crate would close on drop.)
- The engine's outbound tunnel socket MUST be `protect()`'d before the tunnel is built, or packets loop. Non-negotiable.
- Wire state surface mirrors desktop `ClientEvent` / `WireState` (Connecting/Established/Reconnecting/Disconnected + permanent Error).

---

### Task 1: Engine compiles for Android (cdylib + platform module)

Make `vpn-engine` build for `aarch64-linux-android` with an Android platform module, without touching desktop builds.

**Files:**
- Modify: `crates/vpn-engine/Cargo.toml` (add `crate-type` for android; add android deps)
- Create: `crates/vpn-engine/src/platform/android.rs`
- Modify: `crates/vpn-engine/src/platform/mod.rs:8-30` (wire android, exclude from the `compile_error!`)

**Interfaces:**
- Produces: `platform::android` compiles; the `compile_error!` no longer fires for `target_os = "android"`.

- [ ] **Step 1: Add android target + rustup NDK linker prerequisite check**

Run:
```bash
rustup target add aarch64-linux-android x86_64-linux-android
```
Expected: targets installed (or "up to date").

- [ ] **Step 2: Add cdylib crate-type and android-only deps to `crates/vpn-engine/Cargo.toml`**

Under `[lib]` (add if absent):
```toml
[lib]
crate-type = ["lib", "cdylib"]
```
Add an android-only dependency block:
```toml
[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"
libc = "0.2"
ndk-context = "0.1"
```

- [ ] **Step 3: Create `crates/vpn-engine/src/platform/android.rs`**

```rust
//! Android platform surface. Unlike the desktop modules, Android does NOT open
//! `/dev/net/tun` or install OS routes: the system `VpnService` hands us a
//! pre-opened TUN fd and configures routes/DNS/MTU via `VpnService.Builder`.
//! This module therefore exposes the same *names* as the other platforms but the
//! route operations are no-ops (see `routing.rs` android branch and
//! `tun_device::open_tun_from_fd`).
#![allow(dead_code)]
```

- [ ] **Step 4: Wire android into `platform/mod.rs`**

Modify `crates/vpn-engine/src/platform/mod.rs`. Add after the windows block:
```rust
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::*;
```
Change the trailing guard to include android:
```rust
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
compile_error!("unsupported target platform: only linux, macos, windows, and android are supported");
```

- [ ] **Step 5: Verify desktop still builds**

Run: `cargo build -p vpn-engine`
Expected: PASS (host build unaffected).

- [ ] **Step 6: Verify android target compiles (config/link may need NDK; a `cargo check` avoids linking)**

Run: `cargo check -p vpn-engine --target aarch64-linux-android`
Expected: type-checks. (If the linker is missing, that's a Task 7 concern — `cargo check` should still pass. If cargo cannot find the target sysroot at all, note it and continue; the definitive android build is validated in Task 7.)

- [ ] **Step 7: Commit**

```bash
git add crates/vpn-engine/Cargo.toml crates/vpn-engine/src/platform/
git commit -m "feat(engine): add Android platform module and cdylib crate-type"
```

---

### Task 2: `open_tun_from_fd` — wrap an externally-provided TUN fd

On Android the fd is already open; wrap it into the same `TunDevice` async surface without IP assignment or bring-up.

**Files:**
- Modify: `crates/vpn-engine/src/tun_device.rs` (add android-only constructor)
- Test: `crates/vpn-engine/src/tun_device.rs` (inline `#[cfg(test)]` module, android-gated test uses a socketpair)

**Interfaces:**
- Consumes: a raw fd (`std::os::fd::RawFd`) + `&SessionParams`.
- Produces: `#[cfg(target_os = "android")] pub fn open_tun_from_fd(fd: RawFd, params: &SessionParams) -> Result<TunDevice, VpnError>` returning a `TunDevice` whose `split()` yields working async read/write halves. `name()` returns `"tun-android"` (Android hides the real interface name from apps).

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/vpn-engine/src/tun_device.rs`:
```rust
#[cfg(all(test, target_os = "android"))]
mod android_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_params() -> crate::tunnel::SessionParams {
        crate::tunnel::SessionParams {
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: None,
            dns: vec![],
            mtu: 1400,
            keepalive: None,
            dpd: None,
            disconnected_timeout: None,
        }
    }

    #[tokio::test]
    async fn wraps_external_fd_and_roundtrips() {
        // A socketpair stands in for the kernel TUN fd: bytes written to one end
        // are readable on the other, exercising the async split halves.
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        let (engine_fd, peer_fd) = (fds[0], fds[1]);

        let tun = open_tun_from_fd(engine_fd, &test_params()).expect("wrap fd");
        assert_eq!(tun.name(), "tun-android");
        let (mut r, mut w) = tun.split();

        // Write from the engine side; read it back on the peer via std.
        w.write_all(b"hello").await.unwrap();
        let mut peer = unsafe { std::fs::File::from_raw_fd(peer_fd) };
        use std::io::Read;
        let mut buf = [0u8; 5];
        peer.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        // And the reverse direction into the engine read half.
        use std::io::Write;
        peer.write_all(b"world").unwrap();
        let mut rbuf = [0u8; 5];
        r.read_exact(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf, b"world");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p vpn-engine --target aarch64-linux-android open_tun_from_fd 2>&1 | head`
Expected: FAIL — `open_tun_from_fd` not found. (If android test execution is unavailable on the dev host, this test is validated on-device in Task 7's smoke test; note that and proceed to implement.)

- [ ] **Step 3: Implement `open_tun_from_fd`**

Add near `open_tun` in `crates/vpn-engine/src/tun_device.rs`:
```rust
/// Android: wrap a TUN fd already opened by the system `VpnService` into a
/// `TunDevice`. No IP/bring-up/routes here — the Kotlin `VpnService.Builder`
/// owns all of that. The fd is DUPLICATED so dropping the `tun` device does not
/// close the descriptor the VpnService still owns.
#[cfg(target_os = "android")]
pub fn open_tun_from_fd(
    fd: std::os::fd::RawFd,
    params: &SessionParams,
) -> Result<TunDevice, VpnError> {
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

    // Duplicate: the VpnService retains ownership of the original fd.
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(VpnError::Tun(format!(
            "dup() of VpnService TUN fd failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut config = tun::Configuration::default();
    // The `tun` 0.7 backend accepts a raw fd; it must NOT reconfigure the
    // interface (the system already did). MTU is informational for framing.
    config.raw_fd(dup).mtu(config_mtu(params));

    let device = tun::create_as_async(&config)
        .map_err(|e| VpnError::Tun(format!("wrap android TUN fd failed: {e}")))?;

    Ok(TunDevice {
        device,
        name: "tun-android".to_string(),
    })
}
```

If `TunDevice`'s fields are private to the impl block, this constructor lives in the same module so field access is fine. If the `tun` 0.7 API differs (`raw_fd` vs `RawFd` setter), consult `tun` docs and adjust the builder call — the contract (wrap a dup'd fd, no reconfigure) is fixed.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p vpn-engine --target aarch64-linux-android open_tun_from_fd`
Expected: PASS (or deferred to on-device per Step 2 note).

- [ ] **Step 5: Commit**

```bash
git add crates/vpn-engine/src/tun_device.rs
git commit -m "feat(engine): add open_tun_from_fd for Android VpnService fd"
```

---

### Task 3: Android routing is a no-op guard

`run_pipeline` calls `routing::RoutingGuard::install_routes`. On Android routes are the Builder's job, so provide a no-op that satisfies the same type.

**Files:**
- Modify: `crates/vpn-engine/src/routing.rs` (android-gated `install_routes` / `RoutingGuard`)
- Test: `crates/vpn-engine/src/routing.rs` (inline android-gated test)

**Interfaces:**
- Consumes: `ifindex: u32`, `routes: &[(Ipv4Addr, u8)]`.
- Produces: on android, `RoutingGuard::install_routes(ifindex, routes)` returns `Ok(RoutingGuard)` without touching the OS; `Drop` is a no-op. Same signature the desktop code exposes so `run_pipeline` stays cfg-free.

- [ ] **Step 1: Inspect the existing `RoutingGuard` surface**

Run: `grep -n "pub struct RoutingGuard\|impl RoutingGuard\|pub async fn install_routes\|impl Drop for RoutingGuard" crates/vpn-engine/src/routing.rs`
Expected: shows the desktop signature to mirror exactly (async fn, returns `Result<RoutingGuard, VpnError>`).

- [ ] **Step 2: Write the failing test**

Add to `crates/vpn-engine/src/routing.rs`:
```rust
#[cfg(all(test, target_os = "android"))]
mod android_routing_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn install_routes_is_noop_ok() {
        let guard = RoutingGuard::install_routes(0, &[(Ipv4Addr::new(10, 0, 0, 0), 8)])
            .await
            .expect("android routing is a no-op and must succeed");
        drop(guard); // Drop must not panic or touch the OS.
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo check -p vpn-engine --target aarch64-linux-android`
Expected: FAIL — the android `install_routes` doesn't exist yet (desktop impls are cfg'd out for android).

- [ ] **Step 4: Implement the android no-op guard**

Add to `crates/vpn-engine/src/routing.rs`, gated for android and mirroring the desktop signature:
```rust
/// Android: routing is configured by `VpnService.Builder` on the Kotlin side, so
/// the engine installs nothing. This guard exists only to keep `run_pipeline`
/// free of `#[cfg]` — it holds nothing and its Drop does nothing.
#[cfg(target_os = "android")]
pub struct RoutingGuard;

#[cfg(target_os = "android")]
impl RoutingGuard {
    pub async fn install_routes(
        _ifindex: u32,
        _routes: &[(std::net::Ipv4Addr, u8)],
    ) -> Result<Self, crate::error::VpnError> {
        tracing::info!("android: routes are configured by VpnService.Builder — engine no-op");
        Ok(RoutingGuard)
    }
}
```
Ensure the desktop `RoutingGuard` and its `install_routes`/`Drop` are gated `#[cfg(not(target_os = "android"))]` if they are not already target-gated, so the two definitions don't collide.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p vpn-engine --target aarch64-linux-android install_routes_is_noop_ok`
Expected: PASS (or deferred on-device).

- [ ] **Step 6: Commit**

```bash
git add crates/vpn-engine/src/routing.rs
git commit -m "feat(engine): no-op RoutingGuard on Android (Builder owns routes)"
```

---

### Task 4: Android run entry + `run_pipeline` fd injection + JNI shim

Give the engine an Android entry point that carries the TUN fd, and make `run_pipeline` use `open_tun_from_fd` on android. Expose it to Kotlin via a `#[no_mangle]` JNI function.

**Files:**
- Modify: `crates/vpn-engine/src/client.rs:95-128` (fd injection into `run_pipeline`), and add `run_client_supervised_android`
- Create: `crates/vpn-engine/src/jni_bridge.rs` (android-only JNI export)
- Modify: `crates/vpn-engine/src/lib.rs` (add `#[cfg(target_os="android")] pub mod jni_bridge;` and re-export the android run fn)

**Interfaces:**
- Consumes: `open_tun_from_fd` (Task 2), android `RoutingGuard` (Task 3), existing `connect`/`ClientEvent`.
- Produces:
  - `#[cfg(target_os="android")] pub async fn run_client_supervised_android(config: &Config, password: &str, tun_fd: RawFd, shutdown_rx: watch::Receiver<bool>, events: mpsc::Sender<ClientEvent>) -> Result<(), VpnError>`
  - A tokio task-local `ANDROID_TUN_FD: RawFd` that `run_pipeline` reads on android.
  - JNI export `Java_app_yellowvpn_plugin_VpnBridge_runEngine` (name matched in Task 6's Kotlin `external fun`).

- [ ] **Step 1: Add the task-local fd and android `run_pipeline` branch**

In `crates/vpn-engine/src/client.rs`, add near the top:
```rust
#[cfg(target_os = "android")]
tokio::task_local! {
    static ANDROID_TUN_FD: std::os::fd::RawFd;
}
```
Change the TUN acquisition in `run_pipeline` (currently `let tun = tun_device::open_tun(params).await?;` and the `if_index`/`install_routes` lines) to branch by platform:
```rust
    #[cfg(not(target_os = "android"))]
    let (tun, routing) = {
        let tun = tun_device::open_tun(params).await?;
        tracing::info!(interface = %tun.name(), "TUN interface ready");
        let ifindex = tun.if_index()?;
        let routing = routing::RoutingGuard::install_routes(ifindex, routes).await?;
        tracing::info!(ifindex, route_count = routes.len(), "VPN routes installed");
        (tun, routing)
    };
    #[cfg(target_os = "android")]
    let (tun, routing) = {
        let fd = ANDROID_TUN_FD.get();
        let tun = tun_device::open_tun_from_fd(fd, params)?;
        tracing::info!("android: wrapped VpnService TUN fd");
        // ifindex unused on android; routes handled by the Builder.
        let routing = routing::RoutingGuard::install_routes(0, routes).await?;
        (tun, routing)
    };
```
(The rest of `run_pipeline` — `*established = true`, event send, `forward::run_forwarding(stream, tun, routing, ...)` — is unchanged.)

- [ ] **Step 2: Add `run_client_supervised_android`**

Append to `crates/vpn-engine/src/client.rs`:
```rust
/// Android entry: same reconnect/supervision loop as `run_client_supervised`,
/// but the TUN fd (opened by the system VpnService) is injected via a task-local
/// that `run_pipeline` reads instead of opening `/dev/net/tun`.
#[cfg(target_os = "android")]
pub async fn run_client_supervised_android(
    config: &Config,
    password: &str,
    tun_fd: std::os::fd::RawFd,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    events: tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    ANDROID_TUN_FD
        .scope(tun_fd, run_client_supervised(config, password, shutdown_rx, events))
        .await
}
```

- [ ] **Step 3: Create the JNI bridge `crates/vpn-engine/src/jni_bridge.rs`**

```rust
//! JNI export consumed by the Kotlin `VpnService` plugin. Kotlin passes the
//! connection config (host/port/user/password), the protected TUN fd, and gets
//! state callbacks. A single blocking call that owns a tokio runtime for the
//! connection's lifetime; Kotlin runs it on a background thread.
#![cfg(target_os = "android")]

use jni::objects::{JClass, JObject, JString};
use jni::sys::jint;
use jni::JNIEnv;

use crate::config::{Config, Protocol};
use crate::client::{run_client_supervised_android, ClientEvent};

/// Called by Kotlin: `external fun runEngine(host, port, user, pass, tunFd, cb)`.
/// Blocks until the tunnel ends (disconnect or permanent error). State strings
/// ("connecting"/"established"/"reconnecting"/"disconnected"/"error:<msg>") are
/// delivered to the Kotlin callback object's `onState(String)` method.
#[no_mangle]
pub extern "system" fn Java_app_yellowvpn_plugin_VpnBridge_runEngine(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jint,
    user: JString,
    pass: JString,
    tun_fd: jint,
    callback: JObject,
) {
    let host: String = env.get_string(&host).map(Into::into).unwrap_or_default();
    let user: String = env.get_string(&user).map(Into::into).unwrap_or_default();
    let pass: String = env.get_string(&pass).map(Into::into).unwrap_or_default();

    let config = Config {
        host,
        port: port as u16,
        username: user,
        password: None,
        verbose: false,
        protocol: Protocol::AnyConnect,
        // NOTE: fill remaining Config fields from their Default/desktop mapping;
        // see config.rs. Do not invent fields.
        ..Config::default()
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let _ = shutdown_tx; // A2 wires disconnect; A1 runs until the tunnel ends.
    let (etx, mut erx) = tokio::sync::mpsc::channel::<ClientEvent>(16);

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = call_on_state(&mut env, &callback, &format!("error:{e}"));
            return;
        }
    };

    rt.block_on(async move {
        let cb_env_ptr = &mut env as *mut JNIEnv;
        // Pump events to Kotlin.
        let pump = async {
            while let Some(ev) = erx.recv().await {
                let s = match ev {
                    ClientEvent::Connecting => "connecting".to_string(),
                    ClientEvent::Established => "established".to_string(),
                    ClientEvent::Reconnecting => "reconnecting".to_string(),
                    ClientEvent::Disconnected => "disconnected".to_string(),
                };
                // SAFETY: single-threaded block_on; env used serially.
                let env = unsafe { &mut *cb_env_ptr };
                let _ = call_on_state(env, &callback, &s);
            }
        };
        let run = run_client_supervised_android(&config, &pass, tun_fd, shutdown_rx, etx);
        tokio::pin!(pump);
        let res = tokio::select! {
            r = run => r,
            _ = &mut pump => Ok(()),
        };
        if let Err(e) = res {
            let env = unsafe { &mut *cb_env_ptr };
            let _ = call_on_state(env, &callback, &format!("error:{e}"));
        }
    });
}

fn call_on_state(env: &mut JNIEnv, cb: &JObject, state: &str) -> jni::errors::Result<()> {
    let jstr = env.new_string(state)?;
    env.call_method(cb, "onState", "(Ljava/lang/String;)V", &[(&jstr).into()])?;
    Ok(())
}
```
NOTE for the implementer: match `ClientEvent`'s real variants (check `client.rs` — if `Reconnecting` carries a field, format accordingly). Fill `Config`'s remaining fields from `config.rs` (do not guess field names). The exported symbol name MUST equal `Java_<package>_VpnBridge_runEngine` with the package chosen in Task 5 (`app.yellowvpn.plugin`).

- [ ] **Step 4: Register the module in `lib.rs`**

Add to `crates/vpn-engine/src/lib.rs`:
```rust
#[cfg(target_os = "android")]
pub mod jni_bridge;

#[cfg(target_os = "android")]
pub use client::run_client_supervised_android;
```

- [ ] **Step 5: Verify desktop + android both type-check**

Run: `cargo build -p vpn-engine && cargo check -p vpn-engine --target aarch64-linux-android`
Expected: desktop PASS; android type-checks (link deferred to Task 7).

- [ ] **Step 6: Commit**

```bash
git add crates/vpn-engine/src/client.rs crates/vpn-engine/src/jni_bridge.rs crates/vpn-engine/src/lib.rs
git commit -m "feat(engine): Android run entry with TUN-fd injection and JNI export"
```

---

### Task 5: Tauri Kotlin plugin — VpnService, consent, Builder, foreground service, protect()

The Android-native half: a Tauri mobile plugin that owns the `VpnService`, obtains consent, builds the tunnel, `protect()`s the engine socket, and starts a foreground service.

**Files:**
- Create: `src-tauri/gen/android/app/src/main/java/app/yellowvpn/plugin/YellowVpnService.kt`
- Create: `src-tauri/gen/android/app/src/main/java/app/yellowvpn/plugin/VpnBridge.kt`
- Modify: `src-tauri/gen/android/app/src/main/AndroidManifest.xml` (service + permissions)

**Interfaces:**
- Consumes: the engine JNI export `runEngine(...)` (Task 4).
- Produces:
  - `object VpnBridge { external fun runEngine(host: String, port: Int, user: String, pass: String, tunFd: Int, cb: StateCallback) }` — `System.loadLibrary("vpn_engine")` in its `init`.
  - `class YellowVpnService : VpnService` with `fun startTunnel(config): Int` returning the TUN fd, plus `protect(socketFd)` usage and foreground-service startup.
  - `interface StateCallback { fun onState(state: String) }`.

- [ ] **Step 1: Declare the VpnService and permissions in `AndroidManifest.xml`**

Add inside `<manifest>`:
```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```
Add inside `<application>`:
```xml
<service
    android:name="app.yellowvpn.plugin.YellowVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:foregroundServiceType="specialUse"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

- [ ] **Step 2: Create `VpnBridge.kt` (JNI loader + callback interface)**

```kotlin
package app.yellowvpn.plugin

interface StateCallback {
    fun onState(state: String)
}

object VpnBridge {
    init {
        System.loadLibrary("vpn_engine")
    }
    // Matches the Rust #[no_mangle] Java_app_yellowvpn_plugin_VpnBridge_runEngine.
    external fun runEngine(
        host: String,
        port: Int,
        user: String,
        pass: String,
        tunFd: Int,
        cb: StateCallback,
    )
}
```

- [ ] **Step 3: Create `YellowVpnService.kt` (Builder + protect + foreground)**

```kotlin
package app.yellowvpn.plugin

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlin.concurrent.thread

class YellowVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val host = intent?.getStringExtra("host") ?: return START_NOT_STICKY
        val port = intent.getIntExtra("port", 443)
        val user = intent.getStringExtra("user") ?: ""
        val pass = intent.getStringExtra("pass") ?: ""
        val address = intent.getStringExtra("address") ?: "10.0.0.2"
        val mtu = intent.getIntExtra("mtu", 1400)

        startForeground(1, buildNotification())

        // Build the tunnel: VpnService.Builder owns routes/DNS/MTU (engine skips them).
        val builder = Builder()
            .setSession("Yellow VPN")
            .addAddress(address, 32)
            .addRoute("0.0.0.0", 0)   // A1: full-tunnel; split ranges are A2.
            .setMtu(mtu)
        val pfd = builder.establish() ?: run {
            stopSelf(); return START_NOT_STICKY
        }
        tun = pfd
        val tunFd = pfd.fd

        // Run the Rust engine on a background thread; it blocks for the tunnel's life.
        thread(name = "yellow-vpn-engine") {
            VpnBridge.runEngine(host, port, user, pass, tunFd, object : StateCallback {
                override fun onState(state: String) {
                    // A1: log; Task 6 forwards this to the Tauri event bus.
                    android.util.Log.i("YellowVpn", "state=$state")
                }
            })
            stopSelf()
        }
        return START_STICKY
    }

    // protect() keeps the engine's own outbound socket OUTSIDE the tunnel, so its
    // packets don't loop back through the VPN route. Called from the engine path
    // that creates the socket (see note below).
    fun protectSocket(socketFd: Int): Boolean = protect(socketFd)

    private fun buildNotification(): Notification {
        val chanId = "yellow-vpn"
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(chanId, "Yellow VPN", NotificationManager.IMPORTANCE_LOW)
        )
        return Notification.Builder(this, chanId)
            .setContentTitle("Yellow VPN")
            .setContentText("VPN connection active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .build()
    }

    override fun onDestroy() {
        tun?.close()
        tun = null
        super.onDestroy()
    }
}
```

- [ ] **Step 4: Resolve the `protect()` timing**

`protect()` must be applied to the engine's outbound TCP socket. Two acceptable wirings — pick one and document it in a code comment:
- **(a) Preferred:** pass the `VpnService` reference (or a protect callback) into the JNI call so the engine calls back to `protect(fd)` right after it opens the TLS socket, before connecting. This needs a small extension to the JNI signature in Task 4 (add a `protect` callback object). If you choose this, update Task 4's `runEngine` signature and the Rust socket-creation path together.
- **(b) A1 shortcut:** use `Builder.addDisallowedApplication(packageName)` to exclude the app's own package from the tunnel, sidestepping the loop without a per-socket `protect()`. Simpler for A1; note the limitation (excludes ALL app traffic, not just the tunnel socket).

For A1, implement **(b)** to keep the JNI surface minimal, and leave a `// TODO(A2): switch to per-socket protect()` comment. Add before `.establish()`:
```kotlin
            .addDisallowedApplication(packageName)
```

- [ ] **Step 5: Verify the Kotlin compiles within the gradle project**

Run: `cd src-tauri/gen/android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. (If the `.so` isn't staged yet, `System.loadLibrary` fails only at runtime, not compile time — that's Task 7.)

- [ ] **Step 6: Commit**

```bash
git add src-tauri/gen/android/app/src/main/
git commit -m "feat(android): VpnService plugin with Builder, foreground service, JNI bridge"
```

---

### Task 6: Wire connect/disconnect from Tauri + consent flow + state events

Connect the existing `vpn_connect`/`vpn_disconnect` command surface to the Android service, including the system consent intent, and forward engine state to the UI.

**Files:**
- Create: `src-tauri/gen/android/app/src/main/java/app/yellowvpn/plugin/VpnController.kt`
- Modify: `src-tauri/src/lib.rs` (android-gated `vpn_connect`/`vpn_disconnect` that dispatch to the service instead of the pipe helper)

**Interfaces:**
- Consumes: `YellowVpnService` (Task 5), the desktop `vpn_connect(config)` command shape.
- Produces: on android, `vpn_connect` triggers `VpnService.prepare()` then starts `YellowVpnService`; `vpn_disconnect` stops it. State strings are emitted on the same Tauri event channel `useVpnState.ts` already listens to.

- [ ] **Step 1: Create `VpnController.kt` — consent + service start/stop**

```kotlin
package app.yellowvpn.plugin

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService

object VpnController {
    const val REQ_CONSENT = 0x7601

    /** Returns an Intent if consent is required (caller must startActivityForResult),
     *  or null if already granted. */
    fun consentIntent(ctx: Context): Intent? = VpnService.prepare(ctx)

    fun start(ctx: Context, host: String, port: Int, user: String, pass: String,
              address: String, mtu: Int) {
        val i = Intent(ctx, YellowVpnService::class.java).apply {
            putExtra("host", host); putExtra("port", port)
            putExtra("user", user); putExtra("pass", pass)
            putExtra("address", address); putExtra("mtu", mtu)
        }
        ctx.startForegroundService(i)
    }

    fun stop(ctx: Context) {
        ctx.stopService(Intent(ctx, YellowVpnService::class.java))
    }
}
```

- [ ] **Step 2: Android-gate the pipe-based commands in `src-tauri/src/lib.rs`**

The desktop `vpn_connect`/`vpn_disconnect` talk to the elevated helper via `pipe.rs`. That path does not exist on Android. Wrap the existing command bodies:
```rust
#[cfg(not(target_os = "android"))]
// ... existing pipe-based vpn_connect / vpn_disconnect unchanged ...

#[cfg(target_os = "android")]
#[tauri::command]
async fn vpn_connect(app: tauri::AppHandle, config: WireConfig, password: String) -> Result<(), String> {
    // Delegate to the Kotlin VpnController through the Tauri Android plugin channel.
    // Consent + service start happen on the Android side; see VpnController.kt.
    crate::android_vpn::connect(&app, config, password).await.map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
async fn vpn_disconnect(app: tauri::AppHandle) -> Result<(), String> {
    crate::android_vpn::disconnect(&app).await.map_err(|e| e.to_string())
}
```
Create `src-tauri/src/android_vpn.rs` (android-gated `mod`) that uses the Tauri mobile plugin API to call into `VpnController` and to run the consent `Intent`. Register `#[cfg(target_os="android")] mod android_vpn;` in `lib.rs`. (The exact Tauri v2 mobile plugin-call API — `tauri::plugin` / `run_mobile_plugin` — is version-specific; consult the Tauri v2 mobile docs and follow the generated plugin template already under `gen/android`.)

- [ ] **Step 3: Forward state to the UI event channel**

In the `StateCallback.onState` implementation (Task 5, Step 3), replace the log-only body with an emit onto the Tauri event the frontend already consumes. Confirm the event name first:
Run: `grep -rn "listen(\|emit(" src/hooks/useVpnState.ts src-tauri/src/`
Then emit the same event name with a payload matching the desktop `WireState` shape so `useVpnState.ts` needs no change.

- [ ] **Step 4: Verify the app builds and installs on a device/emulator**

Run: `bun run tauri android dev` (with a device/emulator attached)
Expected: app launches; tapping connect shows the system VPN consent dialog.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/lib.rs src-tauri/src/android_vpn.rs src-tauri/gen/android/app/src/main/java/app/yellowvpn/plugin/VpnController.kt
git commit -m "feat(android): wire connect/disconnect, consent flow, and state events"
```

---

### Task 7: NDK build + `.so` staging + end-to-end smoke test

Build `vpn-engine` as a `.so` per ABI with the NDK and stage it into the APK's `jniLibs`, then verify a real tunnel.

**Files:**
- Create: `scripts/build-android-engine.mjs`
- Modify: `package.json` (add `predev`/`prebuild` android hook and a script)
- Modify: `src-tauri/gen/android/app/build.gradle.kts` (point `jniLibs` at the staged dir, if not default)

**Interfaces:**
- Consumes: the cdylib from Task 1, all engine changes.
- Produces: `src-tauri/gen/android/app/src/main/jniLibs/<abi>/libvpn_engine.so` for each target ABI.

- [ ] **Step 1: Add cargo-ndk (or document NDK linker env)**

Run:
```bash
cargo install cargo-ndk
```
Expected: `cargo-ndk` installed. (Alternative: set `CARGO_TARGET_*_LINKER` to the NDK clang wrappers; cargo-ndk automates this.)

- [ ] **Step 2: Create `scripts/build-android-engine.mjs`**

```js
// Build vpn-engine as a .so per Android ABI and stage into the APK jniLibs.
// Usage: node scripts/build-android-engine.mjs [--release]
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const release = process.argv.includes("--release");
const abis = ["arm64-v8a", "x86_64"]; // device + emulator (A1)
const jniLibs = join(root, "src-tauri", "gen", "android", "app", "src", "main", "jniLibs");

execFileSync(
  "cargo",
  ["ndk", "-t", ...abis.flatMap((a) => ["-t", a]).slice(1), "-o", jniLibs,
   "build", "-p", "vpn-engine", ...(release ? ["--release"] : [])],
  { stdio: "inherit", cwd: root },
);
console.log(`staged libvpn_engine.so into ${jniLibs}`);
```
NOTE: the exact `cargo ndk` arg form is `cargo ndk -t arm64-v8a -t x86_64 -o <jniLibs> build -p vpn-engine`. Adjust the array construction to produce exactly that; verify with `--help` if unsure.

- [ ] **Step 3: Add the npm hooks in `package.json`**

```json
"android:engine": "node scripts/build-android-engine.mjs",
"predev:android": "node scripts/build-android-engine.mjs",
"prebuild:android": "node scripts/build-android-engine.mjs --release"
```
(Mirror how `predev:helper`/`prebuild:helper` are wired for desktop; hook these to the android dev/build commands.)

- [ ] **Step 4: Build the `.so` and confirm staging**

Run: `bun run android:engine`
Expected: `libvpn_engine.so` present under `jniLibs/arm64-v8a/` and `jniLibs/x86_64/`.
Verify: `ls -la src-tauri/gen/android/app/src/main/jniLibs/*/libvpn_engine.so`

- [ ] **Step 5: End-to-end smoke test on a device/emulator**

Run: `bun run tauri android dev`
Manual verification checklist:
- App launches; connect triggers the system VPN consent dialog; granting proceeds.
- The persistent notification appears.
- Against a known AnyConnect test gateway: state reaches `established`, and real traffic flows through the tunnel (verify by loading a page / pinging a tunnel-only address).
- Disconnect tears the tunnel down and dismisses the notification.

Document the result (pass/fail per checklist item) in the commit message.

- [ ] **Step 6: Commit**

```bash
git add scripts/build-android-engine.mjs package.json src-tauri/gen/android/app/build.gradle.kts
git commit -m "build(android): NDK engine build, jniLibs staging, and E2E smoke test"
```

---

## Notes for the implementer

- **Verify before you build on the desktop path:** after each engine task, run `cargo build -p vpn-engine` (host) to guarantee the desktop stays green — the whole point of the cfg-gating.
- **On-device test gating:** several Rust unit tests are `target_os = "android"`-gated and may not run on the dev host. Where that's the case, the on-device smoke test (Task 7) is the backstop. Don't delete the tests — they run in CI/on-device.
- **Do not touch** `crates/vpn-helper`, `crates/vpn-ipc`, or the desktop `pipe.rs` transport for A1 beyond the `#[cfg]` gates in Task 6.
- **API version drift:** the `tun` 0.7 raw-fd API, the `jni` 0.21 call surface, and the Tauri v2 mobile plugin-call API are the three spots most likely to need small adjustments against current docs. The interface contracts in this plan are fixed; the exact method names may need a doc check.
```
