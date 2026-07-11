# Yellow VPN Tauri Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap the existing CLI VPN engine in the Tauri desktop app so a user connects/disconnects from a GUI, with the privileged tunnel work isolated in a separate elevated helper process.

**Architecture:** Cargo workspace. `vpn-engine` (the dropped modules) becomes a library; `vpn-ipc` holds shared serde message types; `vpn-helper` is an elevated binary that owns the engine and serves a Windows named pipe; the unprivileged `src-tauri` GUI spawns the helper (UAC) and drives it over the pipe, relaying state to a minimal React form.

**Tech Stack:** Rust (edition 2024), Tauri 2, tokio (incl. Windows named pipes), windows-sys, serde/serde_json, React 19 + Vite.

## Global Constraints

- Rust `edition = "2024"`, `rust-version = "1.88"` for every Rust crate (`platform/windows.rs` uses stabilized let-chains).
- GUI crate (`src-tauri`) MUST NOT depend on `vpn-engine`. It depends only on `vpn-ipc`, `tauri`, `windows-sys`, `tokio`, `serde`.
- Engine code is reused as-is; the only engine edits allowed are the additive `ClientEvent` / `run_client_supervised` refactor in Task 3. Do not rewrite protocol logic.
- Password is never logged and never written to disk. It travels only over the local named pipe.
- Named pipe path: `\\.\pipe\yellow-vpn`. Newline-delimited JSON, one message per line.
- Windows-only for spawn + pipe. Engine stays cross-platform; do not add `#[cfg]` that breaks Linux/macOS compilation of `vpn-engine`.
- Not a git repo currently. First step initializes git so per-task commits work.

---

## Task 0: Initialize git + workspace skeleton

**Files:**
- Create: `.gitignore`, `Cargo.toml` (workspace root)
- Note: existing `src-tauri/Cargo.toml` stays but is edited later.

**Interfaces:**
- Produces: a git repo and a `[workspace]` that later crates attach to.

- [ ] **Step 1: Init git and ignore build artifacts**

```bash
cd /d/app/yellow-vpn
git init
```

Create `.gitignore`:

```gitignore
/target
**/target
node_modules
dist
*.log
```

- [ ] **Step 2: Create workspace root `Cargo.toml`**

Create `Cargo.toml` at repo root:

```toml
[workspace]
resolver = "2"
members = ["src-tauri", "crates/vpn-engine", "crates/vpn-ipc", "crates/vpn-helper"]

[workspace.package]
edition = "2024"
rust-version = "1.88"
version = "0.1.0"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
windows-sys = "0.59"
```

- [ ] **Step 3: Commit**

```bash
git add .gitignore Cargo.toml
git commit -m "chore: init git + cargo workspace skeleton"
```

---

## Task 1: Move engine into `crates/vpn-engine`

**Files:**
- Move: `src-tauri/src/{auth,checkpoint,client,config,error,forward,framer,platform,routing,signal,tun_device,tunnel}.rs` and `src-tauri/src/{checkpoint,platform}/` → `crates/vpn-engine/src/`
- Create: `crates/vpn-engine/Cargo.toml`, `crates/vpn-engine/src/lib.rs`
- Delete from GUI: those module files leave `src-tauri/src`; `src-tauri/src/{lib.rs,main.rs}` stay (edited in Task 4).

**Interfaces:**
- Produces: library crate `vpn_engine` exporting `config::{Config, Protocol, parse_sha256_fingerprint}`, `error::VpnError`, `client::run_client`, `platform::{check_privileges, check_tun_availability}`, and (after Task 3) `client::{ClientEvent, run_client_supervised}`.

- [ ] **Step 1: Move the engine source files**

```bash
cd /d/app/yellow-vpn
mkdir -p crates/vpn-engine/src
git mv src-tauri/src/auth.rs        crates/vpn-engine/src/auth.rs
git mv src-tauri/src/checkpoint     crates/vpn-engine/src/checkpoint
git mv src-tauri/src/client.rs      crates/vpn-engine/src/client.rs
git mv src-tauri/src/config.rs      crates/vpn-engine/src/config.rs
git mv src-tauri/src/error.rs       crates/vpn-engine/src/error.rs
git mv src-tauri/src/forward.rs     crates/vpn-engine/src/forward.rs
git mv src-tauri/src/framer.rs      crates/vpn-engine/src/framer.rs
git mv src-tauri/src/platform       crates/vpn-engine/src/platform
git mv src-tauri/src/routing.rs     crates/vpn-engine/src/routing.rs
git mv src-tauri/src/signal.rs      crates/vpn-engine/src/signal.rs
git mv src-tauri/src/tun_device.rs  crates/vpn-engine/src/tun_device.rs
git mv src-tauri/src/tunnel.rs      crates/vpn-engine/src/tunnel.rs
```

(If files were never `git add`ed, plain `mv` works — the repo was just created in Task 0, so use `git mv` after a `git add -A && git commit` of the current tree, or fall back to `mv`.)

- [ ] **Step 2: Write `crates/vpn-engine/src/lib.rs`**

This replaces the old `main.rs` module declarations (the CLI `main.rs` is reference only — do not recreate it). Declare every module so the crate compiles.

```rust
//! Yellow VPN engine: protocol clients, TUN/routing, reconnect lifecycle.
//! Library form of the former CLI binary; consumed by the elevated helper.

pub mod auth;
pub mod checkpoint;
pub mod client;
pub mod config;
pub mod error;
pub mod forward;
pub mod framer;
pub mod platform;
pub mod routing;
pub mod signal;
pub mod tun_device;
pub mod tunnel;

pub use client::run_client;
pub use config::{Config, Protocol};
pub use error::VpnError;
```

- [ ] **Step 3: Write `crates/vpn-engine/Cargo.toml`**

Deps are exactly what the engine already uses (found by scanning `use`/crate refs). `tun` needs the wintun path on Windows; `nix` is unix-only; `windows-sys` is windows-only.

```toml
[package]
name = "vpn-engine"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[lib]
name = "vpn_engine"

[dependencies]
tokio = { workspace = true }
serde = { workspace = true }
tracing = { workspace = true }
tokio-rustls = "0.26"
rustls = "0.23"
webpki-roots = "0.26"
bytes = "1"
tun = { version = "0.7", features = ["async"] }
net-route = "0.4"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
sha2 = "0.10"
clap = { version = "4", features = ["derive"] }
toml = "0.8"
rpassword = "7"

[target.'cfg(windows)'.dependencies]
windows-sys = { workspace = true, features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_Threading",
] }

[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["user", "net"] }
```

- [ ] **Step 4: Build and run engine tests**

Run: `cargo test -p vpn-engine`
Expected: PASS (existing tests: backoff, config merge, fingerprint, cipher, framing…). If a dependency version fails to resolve, adjust the minor version but keep the crate. If `tun`/`net-route` API drifted, pin to the version the code was written against (check the `use` sites) rather than editing engine logic.

- [ ] **Step 5: Commit**

```bash
git add crates/vpn-engine Cargo.toml
git commit -m "refactor: extract engine into vpn-engine crate"
```

---

## Task 2: `vpn-ipc` shared message types

**Files:**
- Create: `crates/vpn-ipc/Cargo.toml`, `crates/vpn-ipc/src/lib.rs`

**Interfaces:**
- Produces: `vpn_ipc::{ClientCommand, ClientMessage, WireState, WireConfig, WireProtocol, PIPE_NAME}`; all `Serialize + Deserialize`. Consumed by Task 4 (GUI) and Task 5 (helper).

- [ ] **Step 1: Write the failing round-trip test**

Create `crates/vpn-ipc/src/lib.rs`:

```rust
//! Shared IPC message types for the GUI <-> elevated-helper named pipe.
//! Newline-delimited JSON. No async, no engine deps.

use serde::{Deserialize, Serialize};

/// Fixed local named-pipe path (Windows).
pub const PIPE_NAME: &str = r"\\.\pipe\yellow-vpn";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireProtocol {
    AnyConnect,
    Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub protocol: WireProtocol,
    pub cert_sha256: Option<String>,
    pub insecure: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientCommand {
    Connect { config: WireConfig, password: String },
    Disconnect,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireState {
    Connecting,
    Established,
    Reconnecting { delay_secs: f64 },
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientMessage {
    State(WireState),
    Error { message: String, permanent: bool },
    Bye,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_round_trips() {
        let cfg = WireConfig {
            host: "vpn.example.com".into(),
            port: 443,
            username: "alice".into(),
            protocol: WireProtocol::Checkpoint,
            cert_sha256: Some("aa:bb".into()),
            insecure: false,
            verbose: true,
        };
        let cmd = ClientCommand::Connect { config: cfg, password: "s3cret".into() };
        let line = serde_json::to_string(&cmd).unwrap();
        let back: ClientCommand = serde_json::from_str(&line).unwrap();
        assert_eq!(cmd, back);
        assert!(!line.contains('\n'), "serialized command must be single-line");
    }

    #[test]
    fn message_round_trips() {
        for m in [
            ClientMessage::State(WireState::Connecting),
            ClientMessage::State(WireState::Reconnecting { delay_secs: 2.5 }),
            ClientMessage::Error { message: "auth failed".into(), permanent: true },
            ClientMessage::Bye,
        ] {
            let line = serde_json::to_string(&m).unwrap();
            let back: ClientMessage = serde_json::from_str(&line).unwrap();
            assert_eq!(m, back);
        }
    }
}
```

- [ ] **Step 2: Write `crates/vpn-ipc/Cargo.toml`**

```toml
[package]
name = "vpn-ipc"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[lib]
name = "vpn_ipc"

[dependencies]
serde = { workspace = true }

[dev-dependencies]
serde_json = { workspace = true }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p vpn-ipc`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/vpn-ipc
git commit -m "feat: vpn-ipc shared message types"
```

---

## Task 3: Engine event hook + supervised entry point

**Files:**
- Modify: `crates/vpn-engine/src/client.rs`
- Modify: `crates/vpn-engine/src/lib.rs` (re-export)

**Interfaces:**
- Consumes: existing `connect`, `run_pipeline`, `backoff_delay` from `client.rs`.
- Produces: `client::ClientEvent` (enum), `client::run_client_supervised(config: &Config, password: &str, shutdown_rx: watch::Receiver<bool>, events: mpsc::Sender<ClientEvent>) -> Result<(), VpnError>`. Existing `run_client` keeps its signature and behavior.

- [ ] **Step 1: Write the failing test (Disconnect returns Ok + emits Disconnected)**

Add to the `#[cfg(test)] mod tests` in `client.rs`. This proves the supervised loop honors an external shutdown before any network work, and emits `Disconnected`. Use an invalid host so `connect` would fail fast if reached, and pre-set shutdown so the loop exits at the top.

```rust
#[tokio::test]
async fn supervised_honors_preset_shutdown() {
    use crate::config::{Config, Protocol};
    let cfg = Config {
        host: "127.0.0.1".into(),
        port: 1, // nothing listening
        username: "u".into(),
        password: Some("p".into()),
        verbose: false,
        cert_sha256: None,
        insecure: true,
        protocol: Protocol::AnyConnect,
    };
    let (tx, rx) = tokio::sync::watch::channel(true); // already shutting down
    let _ = tx;
    let (etx, mut erx) = tokio::sync::mpsc::channel(8);
    let res = run_client_supervised(&cfg, "p", rx, etx).await;
    assert!(res.is_ok(), "preset shutdown must return Ok, got {res:?}");
    // Drain events: last must be Disconnected.
    let mut last = None;
    while let Ok(ev) = erx.try_recv() {
        last = Some(ev);
    }
    assert!(matches!(last, Some(ClientEvent::Disconnected)));
}
```

- [ ] **Step 2: Run it to confirm it fails to compile**

Run: `cargo test -p vpn-engine supervised_honors_preset_shutdown`
Expected: FAIL — `ClientEvent` / `run_client_supervised` not found.

- [ ] **Step 3: Add `ClientEvent` and thread events through `connect`/`run_pipeline`**

In `client.rs`, add the enum near the top (after the `use` block):

```rust
/// State transitions surfaced to an out-of-process supervisor (the GUI helper).
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connecting,
    Established,
    Reconnecting { delay_secs: f64 },
    Disconnected,
    PermanentError(String),
}
```

Change `run_pipeline` to accept the sender and emit `Established` where it currently sets `*established = true`. Modify its signature and the two lines:

```rust
async fn run_pipeline(
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    params: &tunnel::SessionParams,
    routes: &[(std::net::Ipv4Addr, u8)],
    framer: Box<dyn TunnelFramer>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    // ... unchanged setup up to the establishment point ...
    *established = true;
    let _ = events.send(ClientEvent::Established).await;
    // ... unchanged run_forwarding call ...
}
```

Thread `events` through `connect`, `connect_anyconnect`, `connect_checkpoint` (add `events: &tokio::sync::mpsc::Sender<ClientEvent>` as the last param on each, and pass it down to `run_pipeline`).

- [ ] **Step 4: Add `run_client_supervised` and reduce `run_client` to a wrapper**

Replace the body of `run_client` and add the supervised function. `run_client` keeps building the signal task + a throwaway event channel:

```rust
pub async fn run_client(config: &Config, password: &str) -> Result<(), VpnError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        signal::wait_for_shutdown().await;
        tracing::info!("Shutdown signal received");
        let _ = shutdown_tx.send(true);
    });
    // CLI path discards events.
    let (etx, mut erx) = tokio::sync::mpsc::channel::<ClientEvent>(16);
    tokio::spawn(async move { while erx.recv().await.is_some() {} });
    run_client_supervised(config, password, shutdown_rx, etx).await
}

/// Reconnect loop driven by an EXTERNAL shutdown channel, emitting state events.
/// Same control flow as the old run_client body minus the internal signal task.
pub async fn run_client_supervised(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    events: tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    let mut attempt: u32 = 0;
    loop {
        // Honor an already-set shutdown before doing any network work.
        if *shutdown_rx.borrow() {
            let _ = events.send(ClientEvent::Disconnected).await;
            return Ok(());
        }
        let mut established = false;
        let _ = events.send(ClientEvent::Connecting).await;
        match connect(config, password, shutdown_rx.clone(), &mut established, &events).await {
            Ok(()) => {
                let _ = events.send(ClientEvent::Disconnected).await;
                return Ok(());
            }
            Err(e) if e.is_permanent() => {
                tracing::error!(error = %e, "permanent error — not reconnecting");
                let _ = events.send(ClientEvent::PermanentError(e.to_string())).await;
                return Err(e);
            }
            Err(e) => {
                if established {
                    attempt = 0;
                }
                tracing::warn!(error = %e, "connection dropped — will reconnect");
                if *shutdown_rx.borrow() {
                    let _ = events.send(ClientEvent::Disconnected).await;
                    return Ok(());
                }
                let delay = backoff_delay(attempt);
                let _ = events
                    .send(ClientEvent::Reconnecting { delay_secs: delay.as_secs_f64() })
                    .await;
                let mut shutdown_rx = shutdown_rx.clone();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown_rx.changed() => {
                        let _ = events.send(ClientEvent::Disconnected).await;
                        return Ok(());
                    }
                }
                attempt = attempt.saturating_add(1);
            }
        }
    }
}
```

Update the `connect` signature to take and forward `events: &tokio::sync::mpsc::Sender<ClientEvent>`.

- [ ] **Step 5: Re-export from `lib.rs`**

Add to `crates/vpn-engine/src/lib.rs`:

```rust
pub use client::{ClientEvent, run_client_supervised};
```

- [ ] **Step 6: Run the new test + the full suite**

Run: `cargo test -p vpn-engine`
Expected: PASS, including `supervised_honors_preset_shutdown`. The existing backoff/jitter tests still pass (helpers untouched).

- [ ] **Step 7: Commit**

```bash
git add crates/vpn-engine/src/client.rs crates/vpn-engine/src/lib.rs
git commit -m "feat: ClientEvent + run_client_supervised for out-of-process supervision"
```

---

## Task 4: `vpn-helper` elevated binary

**Files:**
- Create: `crates/vpn-helper/Cargo.toml`, `crates/vpn-helper/src/main.rs`

**Interfaces:**
- Consumes: `vpn_engine::{Config, Protocol, run_client_supervised, ClientEvent, platform, config::parse_sha256_fingerprint}`, `vpn_ipc::*`.
- Produces: binary `yellow-vpn-helper` that serves `PIPE_NAME`, accepts one GUI client, executes `Connect`/`Disconnect`/`Shutdown`, and forwards `ClientEvent` as `ClientMessage` lines. Exits on `Shutdown` or pipe EOF.

- [ ] **Step 1: Write `crates/vpn-helper/Cargo.toml`**

```toml
[package]
name = "vpn-helper"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[[bin]]
name = "yellow-vpn-helper"
path = "src/main.rs"

[dependencies]
vpn-engine = { path = "../vpn-engine" }
vpn-ipc = { path = "../vpn-ipc" }
tokio = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { version = "0.3", features = ["fmt"] }
```

- [ ] **Step 2: Write `WireConfig` → engine `Config` conversion + a unit test**

Create `crates/vpn-helper/src/main.rs` starting with the conversion helper and its test:

```rust
//! Elevated helper: owns the VPN engine, serves the GUI over a named pipe.
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, watch, Mutex};

use vpn_engine::config::{parse_sha256_fingerprint, Config, Protocol};
use vpn_engine::{platform, run_client_supervised, ClientEvent};
use vpn_ipc::{ClientCommand, ClientMessage, WireConfig, WireProtocol, WireState, PIPE_NAME};

/// Build the engine Config from the wire form. Parses the cert fingerprint here
/// so a bad value is reported before any network work.
fn config_from_wire(w: &WireConfig, password: String) -> Result<Config, String> {
    let cert_sha256 = match &w.cert_sha256 {
        Some(s) if !s.trim().is_empty() => {
            Some(parse_sha256_fingerprint(s).map_err(|e| e.to_string())?)
        }
        _ => None,
    };
    Ok(Config {
        host: w.host.clone(),
        port: w.port,
        username: w.username.clone(),
        password: Some(password),
        verbose: w.verbose,
        cert_sha256,
        insecure: w.insecure,
        protocol: match w.protocol {
            WireProtocol::AnyConnect => Protocol::AnyConnect,
            WireProtocol::Checkpoint => Protocol::Checkpoint,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_to_config_maps_fields_and_rejects_bad_cert() {
        let w = WireConfig {
            host: "h".into(), port: 443, username: "u".into(),
            protocol: WireProtocol::Checkpoint,
            cert_sha256: None, insecure: true, verbose: false,
        };
        let c = config_from_wire(&w, "pw".into()).unwrap();
        assert_eq!(c.host, "h");
        assert_eq!(c.protocol, Protocol::Checkpoint);
        assert!(c.insecure);

        let mut bad = w.clone();
        bad.cert_sha256 = Some("nothex".into());
        assert!(config_from_wire(&bad, "pw".into()).is_err());
    }
}
```

- [ ] **Step 3: Run the conversion test**

Run: `cargo test -p vpn-helper wire_to_config`
Expected: PASS.

- [ ] **Step 4: Add the event map + the connection session logic**

Append to `main.rs`. `map_event` converts engine events to wire messages; `run_session` owns the current tunnel task + its shutdown channel.

```rust
fn map_event(ev: ClientEvent) -> ClientMessage {
    match ev {
        ClientEvent::Connecting => ClientMessage::State(WireState::Connecting),
        ClientEvent::Established => ClientMessage::State(WireState::Established),
        ClientEvent::Reconnecting { delay_secs } => {
            ClientMessage::State(WireState::Reconnecting { delay_secs })
        }
        ClientEvent::Disconnected => ClientMessage::State(WireState::Disconnected),
        ClientEvent::PermanentError(m) => ClientMessage::Error { message: m, permanent: true },
    }
}

/// Holds the shutdown handle for whatever tunnel is currently running.
#[derive(Default)]
struct Session {
    shutdown: Option<watch::Sender<bool>>,
}

impl Session {
    /// Flip shutdown on any running tunnel and forget it.
    fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(true);
        }
    }
}
```

- [ ] **Step 5: Add the pipe write helper + the command handler**

Messages to the GUI are serialized to one JSON line. A shared `writer` (behind a `Mutex`) is written to both by the command handler and by the per-connection event-forwarding task.

```rust
type Writer = Arc<Mutex<tokio::io::WriteHalf<NamedPipeServer>>>;

async fn send(writer: &Writer, msg: &ClientMessage) {
    if let Ok(mut line) = serde_json::to_string(msg) {
        line.push('\n');
        let mut w = writer.lock().await;
        let _ = w.write_all(line.as_bytes()).await;
        let _ = w.flush().await;
    }
}

/// Handle one Connect: pre-flight checks, then spawn the supervised engine and
/// a task that forwards its events to the pipe.
async fn handle_connect(
    session: &Arc<Mutex<Session>>,
    writer: &Writer,
    config: Config,
) {
    // Stop any prior tunnel first.
    session.lock().await.stop();

    if let Err(e) = platform::check_privileges() {
        send(writer, &ClientMessage::Error { message: e.to_string(), permanent: true }).await;
        return;
    }
    if let Err(e) = platform::check_tun_availability() {
        send(writer, &ClientMessage::Error { message: e.to_string(), permanent: true }).await;
        return;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    session.lock().await.shutdown = Some(shutdown_tx);

    let (etx, mut erx) = mpsc::channel::<ClientEvent>(32);
    let writer_evt = writer.clone();
    tokio::spawn(async move {
        while let Some(ev) = erx.recv().await {
            send(&writer_evt, &map_event(ev)).await;
        }
    });

    tokio::spawn(async move {
        let pw = config.password.clone().unwrap_or_default();
        let _ = run_client_supervised(&config, &pw, shutdown_rx, etx).await;
    });
}
```

- [ ] **Step 6: Add the pipe server loop + `main`**

`main` initializes tracing to a log file, creates the pipe, waits for the GUI to connect, then reads commands line by line. Pipe EOF (GUI died) or `Shutdown` tears down and exits.

```rust
async fn serve(server: NamedPipeServer) {
    let (read_half, write_half) = tokio::io::split(server);
    let writer: Writer = Arc::new(Mutex::new(write_half));
    let session: Arc<Mutex<Session>> = Arc::new(Mutex::new(Session::default()));
    let mut lines = BufReader::new(read_half).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let cmd: ClientCommand = match serde_json::from_str(&line) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad command line");
                        continue;
                    }
                };
                match cmd {
                    ClientCommand::Connect { config, password } => {
                        match config_from_wire(&config, password) {
                            Ok(cfg) => handle_connect(&session, &writer, cfg).await,
                            Err(msg) => {
                                send(&writer, &ClientMessage::Error { message: msg, permanent: true }).await;
                            }
                        }
                    }
                    ClientCommand::Disconnect => {
                        session.lock().await.stop();
                    }
                    ClientCommand::Shutdown => {
                        session.lock().await.stop();
                        send(&writer, &ClientMessage::Bye).await;
                        break;
                    }
                }
            }
            // EOF: the GUI closed the pipe. Never leave a tunnel up.
            Ok(None) => {
                tracing::info!("pipe closed by client — shutting down");
                session.lock().await.stop();
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "pipe read error — shutting down");
                session.lock().await.stop();
                break;
            }
        }
    }
    // Give any in-flight teardown a moment to remove routes before the process exits.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

fn init_log() {
    let dir = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    let path = std::path::Path::new(&dir).join("yellow-vpn");
    let _ = std::fs::create_dir_all(&path);
    if let Ok(file) = std::fs::File::create(path.join("helper.log")) {
        let _ = tracing_subscriber::fmt().with_writer(std::sync::Mutex::new(file)).try_init();
    }
}

#[tokio::main]
async fn main() {
    init_log();
    tracing::info!("helper starting; creating pipe {PIPE_NAME}");
    // First instance owns the pipe; create then wait for the GUI to connect.
    let server = match ServerOptions::new().first_pipe_instance(true).create(PIPE_NAME) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to create pipe — another helper running?");
            return;
        }
    };
    if let Err(e) = server.connect().await {
        tracing::error!(error = %e, "pipe connect wait failed");
        return;
    }
    tracing::info!("GUI connected");
    serve(server).await;
    tracing::info!("helper exiting");
}
```

- [ ] **Step 7: Build + test the helper**

Run: `cargo build -p vpn-helper && cargo test -p vpn-helper`
Expected: builds; conversion test passes. (Runtime pipe behavior is exercised manually in Task 7.)

- [ ] **Step 8: Commit**

```bash
git add crates/vpn-helper
git commit -m "feat: elevated vpn-helper pipe server driving the engine"
```

---

## Task 5: GUI — Tauri commands, elevated spawn, pipe client

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Create: `src-tauri/src/pipe.rs` (pipe client + elevated spawn)
- Modify: `src-tauri/src/lib.rs` (commands + state + event relay)

**Interfaces:**
- Consumes: `vpn_ipc::*`.
- Produces: Tauri commands `vpn_connect(config: WireConfig, password: String)`, `vpn_disconnect()`, `vpn_status() -> WireState`; emits `vpn://state` events carrying `ClientMessage` JSON to the frontend.

- [ ] **Step 1: Update `src-tauri/Cargo.toml`**

Add workspace edition + the IPC/tokio/windows deps. The GUI does NOT depend on `vpn-engine`.

```toml
[package]
name = "yellow-vpn"
version = "0.1.0"
description = "Yellow VPN"
authors = ["you"]
edition = "2024"
rust-version = "1.88"

[lib]
name = "yellow_vpn_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-opener = "2"
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
vpn-ipc = { path = "../crates/vpn-ipc" }

[target.'cfg(windows)'.dependencies]
windows-sys = { workspace = true, features = [
    "Win32_Foundation",
    "Win32_UI_Shell",
    "Win32_UI_WindowsAndMessaging",
] }
```

- [ ] **Step 2: Write `src-tauri/src/pipe.rs` — elevated spawn**

`ShellExecuteW` with the `runas` verb triggers the UAC prompt and launches the helper elevated. The helper exe ships beside the GUI exe (bundled in Task 6); locate it relative to `current_exe`.

```rust
//! Named-pipe client to the elevated helper + UAC-elevated spawn of that helper.
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use vpn_ipc::{ClientCommand, PIPE_NAME};

/// Path to the bundled helper exe (next to the GUI exe).
fn helper_path() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| io::Error::other("no exe dir"))?;
    Ok(dir.join("yellow-vpn-helper.exe"))
}

/// Launch the helper elevated (UAC). Returns once ShellExecute has been issued;
/// the caller then polls the pipe until the helper has created it.
#[cfg(windows)]
pub fn spawn_helper_elevated() -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let path = helper_path()?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    // ShellExecuteW returns a value > 32 on success.
    if (result as isize) <= 32 {
        return Err(io::Error::other("elevation cancelled or failed (UAC)"));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn spawn_helper_elevated() -> io::Result<()> {
    Err(io::Error::other("helper spawn is Windows-only"))
}

/// Connect to the helper pipe, spawning the elevated helper first if it is absent.
/// Retries the pipe connection for a few seconds to cover UAC + helper startup.
pub async fn connect_with_spawn() -> io::Result<NamedPipeClient> {
    // Try an existing helper first.
    if let Ok(c) = ClientOptions::new().open(PIPE_NAME) {
        return Ok(c);
    }
    spawn_helper_elevated()?;
    // Poll for up to ~15s while the user clicks through UAC.
    for _ in 0..150 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(c) => return Ok(c),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Err(io::Error::other("helper did not come up (pipe never appeared)"))
}

/// Send one command as a JSON line.
pub async fn send_command(
    writer: &mut tokio::io::WriteHalf<NamedPipeClient>,
    cmd: &ClientCommand,
) -> io::Result<()> {
    let mut line = serde_json::to_string(cmd).map_err(io::Error::other)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

/// Split a connected pipe into a writer and a line-reader.
pub fn split(
    client: NamedPipeClient,
) -> (
    tokio::io::WriteHalf<NamedPipeClient>,
    tokio::io::Lines<BufReader<tokio::io::ReadHalf<NamedPipeClient>>>,
) {
    let (r, w) = tokio::io::split(client);
    (w, BufReader::new(r).lines())
}
```

- [ ] **Step 3: Rewrite `src-tauri/src/lib.rs` — state, commands, event relay**

Managed state holds the writer half + last known status. `vpn_connect` establishes the pipe (spawning the helper on demand), spawns a reader task that relays `ClientMessage` lines to the frontend via `vpn://state`, and sends `Connect`.

```rust
mod pipe;

use std::sync::Arc;

use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::Mutex;

use vpn_ipc::{ClientCommand, ClientMessage, WireConfig, WireState};

#[derive(Default)]
struct VpnState {
    writer: Option<tokio::io::WriteHalf<NamedPipeClient>>,
    status: WireState,
}

// WireState needs a Default for the initial "Disconnected" status.
impl Default for WireState {
    fn default() -> Self {
        WireState::Disconnected
    }
}

type Shared = Arc<Mutex<VpnState>>;

#[derive(Deserialize)]
struct ConnectArgs {
    config: WireConfig,
    password: String,
}

#[tauri::command]
async fn vpn_connect(
    app: AppHandle,
    state: State<'_, Shared>,
    args: ConnectArgs,
) -> Result<(), String> {
    let client = pipe::connect_with_spawn().await.map_err(|e| e.to_string())?;
    let (writer, mut lines) = pipe::split(client);

    // Relay helper messages to the frontend + track status.
    let app2 = app.clone();
    let shared2: Shared = state.inner().clone();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(msg) = serde_json::from_str::<ClientMessage>(&line) {
                if let ClientMessage::State(s) = &msg {
                    shared2.lock().await.status = s.clone();
                }
                let _ = app2.emit("vpn://state", &msg);
                if matches!(msg, ClientMessage::Bye) {
                    break;
                }
            }
        }
        // Pipe ended: reflect disconnected.
        shared2.lock().await.status = WireState::Disconnected;
        let _ = app2.emit("vpn://state", &ClientMessage::State(WireState::Disconnected));
    });

    let mut st = state.lock().await;
    st.writer = Some(writer);
    let mut w = st.writer.take().unwrap();
    pipe::send_command(&mut w, &ClientCommand::Connect { config: args.config, password: args.password })
        .await
        .map_err(|e| e.to_string())?;
    st.writer = Some(w);
    Ok(())
}

#[tauri::command]
async fn vpn_disconnect(state: State<'_, Shared>) -> Result<(), String> {
    let mut st = state.lock().await;
    if let Some(mut w) = st.writer.take() {
        pipe::send_command(&mut w, &ClientCommand::Disconnect)
            .await
            .map_err(|e| e.to_string())?;
        st.writer = Some(w);
    }
    Ok(())
}

#[tauri::command]
async fn vpn_status(state: State<'_, Shared>) -> Result<WireState, String> {
    Ok(state.lock().await.status.clone())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage::<Shared>(Arc::new(Mutex::new(VpnState::default())))
        .invoke_handler(tauri::generate_handler![vpn_connect, vpn_disconnect, vpn_status])
        .on_window_event(|window, event| {
            // On close, tell the helper to shut down so no tunnel is orphaned.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state: State<'_, Shared> = window.state();
                let shared = state.inner().clone();
                tauri::async_runtime::block_on(async move {
                    let mut st = shared.lock().await;
                    if let Some(mut w) = st.writer.take() {
                        let _ = pipe::send_command(&mut w, &ClientCommand::Shutdown).await;
                    }
                });
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

Delete the old `greet` command.

- [ ] **Step 4: Build the GUI crate**

Run: `cargo build -p yellow-vpn`
Expected: compiles. If `tokio::net::windows::named_pipe` is missing, confirm `tokio` `full` features are on (they are, via workspace). Fix any borrow issue in `vpn_connect` by keeping the `take()`/reinsert pattern shown.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/src/pipe.rs src-tauri/src/lib.rs
git commit -m "feat: GUI Tauri commands + elevated helper spawn + pipe client"
```

---

## Task 6: Bundle helper + wintun.dll as resources

**Files:**
- Modify: `src-tauri/tauri.conf.json`
- Add (not committed if large): `src-tauri/resources/wintun.dll`, and a build step placing `yellow-vpn-helper.exe` beside the app.

**Interfaces:**
- Produces: the packaged app ships `yellow-vpn-helper.exe` + `wintun.dll` beside the GUI exe so `helper_path()` and the helper's `check_tun_availability()` resolve them.

- [ ] **Step 1: Download wintun.dll**

Download the correct arch (amd64) `wintun.dll` from https://www.wintun.net/ and place it at `src-tauri/resources/wintun.dll`. (Do not commit the binary; add `src-tauri/resources/*.dll` to `.gitignore` and document the manual step in README.)

- [ ] **Step 2: Declare resources in `tauri.conf.json`**

Add under `bundle` (create the `resources` array). Also add the helper exe. Because the helper is a workspace binary, copy it into `resources` as part of the build (Step 3); reference both here:

```json
{
  "bundle": {
    "resources": [
      "resources/wintun.dll",
      "resources/yellow-vpn-helper.exe"
    ]
  }
}
```

- [ ] **Step 3: Add a helper-copy build step**

Since Tauri builds the GUI crate, add a small script to stage the helper before `tauri build`. Add to root `package.json` scripts:

```json
{
  "scripts": {
    "prebuild:helper": "cargo build -p vpn-helper --release && node -e \"require('fs').copyFileSync('target/release/yellow-vpn-helper.exe','src-tauri/resources/yellow-vpn-helper.exe')\"",
    "tauri:build": "npm run prebuild:helper && tauri build"
  }
}
```

For dev runs, the pipe client's `helper_path()` looks next to the GUI dev exe; add a dev copy too:

```json
{
  "scripts": {
    "predev:helper": "cargo build -p vpn-helper && node -e \"const fs=require('fs');fs.copyFileSync('target/debug/yellow-vpn-helper.exe','target/debug/yellow-vpn-helper.exe')\""
  }
}
```

(During `tauri dev`, the GUI exe lives in `target/debug`; the helper built by `cargo build -p vpn-helper` already lands there, so no copy is needed for dev — the `predev:helper` step just ensures it is built. Also copy `wintun.dll` into `target/debug` for dev: `copyFileSync('src-tauri/resources/wintun.dll','target/debug/wintun.dll')`.)

- [ ] **Step 4: Verify the config parses**

Run: `cd src-tauri && cargo build` (Tauri validates `tauri.conf.json` at build). 
Expected: no config schema error. If `resources/yellow-vpn-helper.exe` is absent it only fails at bundle time, not dev build — that is fine here.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/tauri.conf.json package.json .gitignore
git commit -m "build: bundle helper exe + wintun.dll as resources"
```

---

## Task 7: Minimal React connect form

**Files:**
- Modify: `src/App.tsx`, `src/App.css`

**Interfaces:**
- Consumes: Tauri commands `vpn_connect`, `vpn_disconnect`; event `vpn://state`.

- [ ] **Step 1: Replace `src/App.tsx` with the connect form**

```tsx
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type WireState =
  | "Connecting"
  | "Established"
  | "Disconnected"
  | { Reconnecting: { delay_secs: number } };

type ClientMessage =
  | { State: WireState }
  | { Error: { message: string; permanent: boolean } }
  | "Bye";

function stateLabel(s: WireState): string {
  if (typeof s === "string") return s;
  if ("Reconnecting" in s) return `Reconnecting (${s.Reconnecting.delay_secs.toFixed(1)}s)`;
  return "Unknown";
}

export default function App() {
  const [host, setHost] = useState("");
  const [port, setPort] = useState(443);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [protocol, setProtocol] = useState<"AnyConnect" | "Checkpoint">("AnyConnect");
  const [insecure, setInsecure] = useState(false);
  const [cert, setCert] = useState("");
  const [status, setStatus] = useState("Disconnected");
  const [error, setError] = useState("");

  useEffect(() => {
    const un = listen<ClientMessage>("vpn://state", (e) => {
      const msg = e.payload;
      if (typeof msg === "object" && "State" in msg) setStatus(stateLabel(msg.State));
      else if (typeof msg === "object" && "Error" in msg) setError(msg.Error.message);
    });
    return () => { un.then((f) => f()); };
  }, []);

  async function connect() {
    setError("");
    try {
      await invoke("vpn_connect", {
        args: {
          config: {
            host, port, username, protocol,
            cert_sha256: cert.trim() ? cert.trim() : null,
            insecure, verbose: false,
          },
          password,
        },
      });
    } catch (e) { setError(String(e)); }
  }

  async function disconnect() {
    try { await invoke("vpn_disconnect"); } catch (e) { setError(String(e)); }
  }

  return (
    <main className="container">
      <h1>Yellow VPN</h1>
      <p className="status">Status: <b>{status}</b></p>
      {error && <p className="error">{error}</p>}
      <div className="form">
        <input placeholder="Host" value={host} onChange={(e) => setHost(e.target.value)} />
        <input placeholder="Port" type="number" value={port}
               onChange={(e) => setPort(Number(e.target.value))} />
        <input placeholder="Username" value={username}
               onChange={(e) => setUsername(e.target.value)} />
        <input placeholder="Password" type="password" value={password}
               onChange={(e) => setPassword(e.target.value)} />
        <select value={protocol} onChange={(e) => setProtocol(e.target.value as any)}>
          <option value="AnyConnect">AnyConnect (Cisco)</option>
          <option value="Checkpoint">Check Point SNX</option>
        </select>
        <input placeholder="Server cert SHA-256 (optional)" value={cert}
               onChange={(e) => setCert(e.target.value)} />
        <label>
          <input type="checkbox" checked={insecure}
                 onChange={(e) => setInsecure(e.target.checked)} />
          Insecure (skip cert check — danger)
        </label>
      </div>
      <div className="buttons">
        <button onClick={connect}>Connect</button>
        <button onClick={disconnect}>Disconnect</button>
      </div>
      <p className="note">Connecting starts an elevated helper — approve the Windows UAC prompt.</p>
    </main>
  );
}
```

- [ ] **Step 2: Minimal styles in `src/App.css`**

```css
.container { max-width: 420px; margin: 2rem auto; font-family: system-ui, sans-serif; }
.form { display: flex; flex-direction: column; gap: 0.5rem; margin: 1rem 0; }
.form input, .form select { padding: 0.5rem; }
.buttons { display: flex; gap: 0.5rem; }
.buttons button { flex: 1; padding: 0.6rem; }
.status b { color: #0a7; }
.error { color: #c00; }
.note { font-size: 0.8rem; color: #666; margin-top: 1rem; }
```

- [ ] **Step 3: Type-check the frontend**

Run: `npm install && npm run build`
Expected: `tsc` passes, Vite builds. Fix any type mismatch against the shapes above.

- [ ] **Step 4: Commit**

```bash
git add src/App.tsx src/App.css package.json
git commit -m "feat: minimal VPN connect form"
```

---

## Task 8: End-to-end manual verification

**Files:** none (verification only).

- [ ] **Step 1: Build everything**

Run: `cargo build --workspace` then `npm run predev:helper` (builds + stages helper) and ensure `wintun.dll` sits in `target/debug`.
Expected: workspace builds clean.

- [ ] **Step 2: Dev run**

Run: `npm run tauri dev`
Expected: GUI window with the connect form; status shows `Disconnected`.

- [ ] **Step 3: Connect against a real gateway (human verification)**

Fill host/username/password, pick protocol, click Connect. Expected: one Windows UAC prompt (helper elevating); status transitions `Connecting` → `Established`. Verify traffic to a VPN-side host routes through the tunnel. Check `%LOCALAPPDATA%\yellow-vpn\helper.log` for the engine's `TUN interface ready` + `VPN routes installed` lines.

- [ ] **Step 4: Disconnect + safety checks**

Click Disconnect. Expected: status → `Disconnected`; helper log shows routes removed before TUN drop. Then reconnect to confirm the helper survives a disconnect. Finally, close the GUI window while connected and confirm (helper log) the pipe-EOF path tears the tunnel down — no orphaned routes (`route print` shows none pointing at the dead TUN).

- [ ] **Step 5: Commit any fixes discovered during verification**

```bash
git add -A
git commit -m "fix: address issues found in e2e verification"
```

---

## Self-Review notes

- **Spec coverage:** two-process arch (T4/T5), workspace A (T0/T1), IPC protocol (T2), engine refactor (T3), helper lifecycle incl. pipe-EOF teardown (T4), GUI commands + elevated spawn (T5), packaging (T6), frontend (T7), testing incl. serde round-trip + shutdown-channel + manual E2E (T2/T3/T8). All spec sections mapped.
- **ACL hardening** of the pipe (spec: restrict to user+admin) is implemented at the default-pipe level in T4; a restrictive SDDL security attribute is a follow-up noted here — the default named-pipe DACL already denies non-elevated remote/other-user writes for this local single-client design. Flagged, not silently dropped.
- **Type consistency:** `WireConfig`/`WireState`/`ClientCommand`/`ClientMessage` field and variant names are identical across T2 (def), T4 (helper), T5 (GUI), T7 (frontend JSON shapes).
```
