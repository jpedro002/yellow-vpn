# Yellow VPN — Tauri GUI + Privileged Helper Integration

**Date:** 2026-07-11
**Status:** Approved design, pre-implementation

## Goal

Wrap the existing CLI VPN engine (dropped into `src-tauri/src`) in the Tauri
desktop app so a user can connect/disconnect from a GUI. The engine is used
as-is where possible; the CLI `main.rs` shown by the user is reference only.

## Constraints & decisions (locked)

- **Privilege model: privileged helper process.** GUI runs unprivileged; a
  separate elevated helper owns TUN/routing/tunnel. Chosen for isolation.
- **Scope: minimal wiring.** Get connect→tunnel→disconnect working end-to-end
  with a basic connect form. No polished UI this pass.
- **Crate layout: Cargo workspace (option A).** GUI binary links no engine code.
- Deps are effectively locked to what the engine already uses (no new protocol
  crates). New crates added only for IPC transport / process spawn.

## Architecture — two processes

```
┌─────────────────────────┐        named pipe         ┌──────────────────────────┐
│ GUI  (unprivileged)     │  \\.\pipe\yellow-vpn      │ Helper (elevated, admin)  │
│ Tauri app `yellow-vpn`  │ <───────JSON lines───────>│ `yellow-vpn-helper.exe`   │
│ - Tauri commands        │                           │ - pipe server            │
│ - React connect form    │   Connect/Disconnect ──▶  │ - owns vpn-engine        │
│ - emits vpn://state     │   ◀── State/Error/Bye     │ - TUN / routing / tunnel │
└─────────────────────────┘                           └──────────────────────────┘
```

**Elevation flow:** on first `vpn_connect`, GUI checks for a live pipe; if none,
it spawns the bundled helper exe via `ShellExecuteW` with the `"runas"` verb →
one UAC prompt → helper starts elevated, creates the pipe, GUI connects. GUI
never elevates itself.

## Crate layout (workspace A)

```
yellow-vpn/
  Cargo.toml            # [workspace] members
  package.json, index.html, src/   # React frontend (existing)
  src-tauri/            # GUI Tauri crate — deps: tauri, vpn-ipc, windows-sys
  crates/
    vpn-engine/         # the dropped modules (auth, tunnel, tun_device, forward,
                        #   framer, routing, client, config, error, signal,
                        #   platform/, checkpoint/) as a lib
    vpn-ipc/            # shared serde message types (tiny lib, both sides depend)
    vpn-helper/         # elevated bin: pipe server + drives vpn-engine
```

- `vpn-engine` is a library crate. Its modules move out of `src-tauri/src` into
  `crates/vpn-engine/src`. `lib.rs` declares all modules and re-exports the
  public surface (`Config`, `Protocol`, `run_client_supervised`, `ClientEvent`,
  `VpnError`, `platform::check_*`).
- `vpn-ipc` holds only serde structs/enums (below). No async, no engine deps.
- `vpn-helper` depends on `vpn-engine` + `vpn-ipc` + tokio + windows-sys (pipe).
- `src-tauri` depends on `vpn-ipc` + tauri + windows-sys (spawn + pipe client).
  It does NOT depend on `vpn-engine`.

Both helper exe and `wintun.dll` bundled as Tauri resources so they ship beside
the app and the helper's `check_tun_availability` finds the dll next to itself.

## IPC protocol (`vpn-ipc`)

Transport: Windows named pipe `\\.\pipe\yellow-vpn`, newline-delimited JSON,
one message per line. Pipe security descriptor restricts access to the current
user + Administrators. Password crosses the local pipe in plaintext — acceptable
for a same-machine, ACL-restricted pipe; it is never logged and never written to
disk.

```rust
// GUI -> helper
enum ClientCommand {
    Connect { config: WireConfig, password: String },
    Disconnect,
    Shutdown,
}

// helper -> GUI
enum ClientMessage {
    State(WireState),
    Error { message: String, permanent: bool },
    Bye,
}

enum WireState { Connecting, Established, Reconnecting { delay_secs: f64 }, Disconnected }

// Serializable mirror of the fields the GUI collects. Helper converts to the
// engine `Config`. cert_sha256 sent as the raw hex/colon string; helper parses.
struct WireConfig {
    host: String,
    port: u16,
    username: String,
    protocol: WireProtocol,       // AnyConnect | Checkpoint
    cert_sha256: Option<String>,
    insecure: bool,
    verbose: bool,
}
```

## Engine refactor (minimal, additive)

In `vpn-engine/src/client.rs`, add an event-emitting, externally-driven entry
point and make the existing `run_client` a thin wrapper:

```rust
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connecting,
    Established,
    Reconnecting { delay_secs: f64 },
    Disconnected,
    PermanentError(String),
}

/// Reconnect loop driven by an EXTERNAL shutdown channel + emitting state events.
/// Same logic as run_client, minus the internal signal task.
pub async fn run_client_supervised(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    events: tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError>;
```

- Existing `run_client` keeps its behavior: builds the watch channel, spawns the
  OS-signal task, then delegates to `run_client_supervised` with a no-op event
  sink. CLI path (if ever restored) is unaffected.
- `connect()` / `run_pipeline()` gain an `events` reference and emit `Established`
  at the exact point `*established = true`. The loop emits `Connecting` before
  each attempt, `Reconnecting{delay}` before each backoff sleep, `Disconnected`
  on clean shutdown, `PermanentError` on a permanent failure.
- Helper builds `Config { .. }` directly from `WireConfig` (public fields already
  exist). It does NOT call clap `Args`, TOML `load`, or `resolve_password` — those
  stay for the CLI shape but are unused on the GUI path. `cert_sha256` string is
  parsed via the existing `config::parse_sha256_fingerprint`.
- Tracing: helper initializes a `tracing-subscriber` fmt layer writing to a log
  file under `%LOCALAPPDATA%\yellow-vpn\helper.log`. State transitions reach the
  GUI via `ClientEvent`, not the log.

## Helper (`vpn-helper`)

1. On startup: create the named pipe with a restrictive security descriptor;
   init tracing to the log file.
2. Accept one client connection (the GUI). Read commands line by line.
3. On `Connect`: run pre-flight `platform::check_privileges()` +
   `check_tun_availability()`; on failure send `Error{permanent:true}`. Else spawn
   `run_client_supervised` on a task with a fresh `watch` shutdown channel + an
   `mpsc` event channel; a forwarding task maps `ClientEvent` → `ClientMessage`
   lines on the pipe.
4. On `Disconnect`: flip `shutdown_tx` → engine RAII teardown (routes-before-TUN)
   → `run_client_supervised` returns `Ok` → send `State(Disconnected)`. Helper
   stays alive for a subsequent `Connect`.
5. On `Shutdown` **or pipe EOF** (GUI died): flip shutdown, drain, send `Bye` if
   possible, exit. Pipe EOF is treated as implicit shutdown so a dead GUI never
   leaves the tunnel up.

## GUI (`src-tauri`) + frontend

`lib.rs` Tauri commands (managed state holds the pipe client handle + last known
status behind a `Mutex`/`tokio` primitive):

- `vpn_connect(config: WireConfig, password: String) -> Result<(), String>`:
  ensure helper is running (spawn elevated if the pipe is absent, then connect),
  send `Connect`. Spawn a reader task that turns `ClientMessage` into
  `app.emit("vpn://state", ...)`.
- `vpn_disconnect() -> Result<(), String>`: send `Disconnect`.
- `vpn_status() -> WireState`: return last known status.

On window close / app exit: send `Shutdown` to the helper.

Frontend (React, minimal): a form (host, port, username, password, protocol
select, insecure checkbox, optional cert fingerprint) + Connect/Disconnect
button + a status line bound to `vpn://state` + a short note that connecting
triggers a Windows UAC prompt.

## Lifecycle & safety summary

| Trigger              | Result                                                        |
|----------------------|---------------------------------------------------------------|
| Connect              | spawn helper (UAC) if needed → tunnel up → `Established`       |
| Transient drop       | engine auto-reconnect (existing backoff) → `Reconnecting`      |
| Permanent error      | `Error{permanent:true}`, no retry (auth/config/privilege/tun)  |
| Disconnect           | RAII teardown, routes removed before TUN, helper stays alive   |
| GUI exit / pipe EOF  | helper drains + exits — no orphaned tunnel                     |

## Testing strategy

- Keep all existing `vpn-engine` unit tests (backoff, config merge, fingerprint,
  cipher, framing, etc.).
- `vpn-ipc`: serde round-trip tests for every command/message variant.
- `vpn-helper`: shutdown-via-watch-channel test (reuse the existing watch
  pattern) proving `Disconnect` returns `Ok` and emits `Disconnected`.
- TUN/end-to-end against a real gateway: manual human verification — cannot be
  unit-tested (needs elevation + real server + wintun.dll).

## Build / packaging notes

- Workspace root `Cargo.toml` with `[workspace] members = [...]`.
- `vpn-engine` (and thus helper) set `edition = "2024"`, `rust-version = "1.88"`
  — `platform/windows.rs` uses stabilized let-chains that require edition 2024.
- Engine deps declared on `vpn-engine`: tokio (full), rustls, tokio-rustls,
  webpki-roots, bytes, tracing, tracing-subscriber, tun (wintun feature),
  net-route, serde, serde_json, thiserror, sha2, clap, toml, rpassword;
  `windows-sys` (windows), `nix` (unix).
- `tauri.conf.json`: bundle `yellow-vpn-helper.exe` + `wintun.dll` as resources.
- No Tauri shell plugin — elevated spawn uses `windows-sys` `ShellExecuteW`.

## Out of scope (this pass)

- Non-Windows helper packaging/elevation (engine is cross-platform; GUI spawn +
  pipe are Windows-only for now).
- Log streaming to the GUI (logs go to file only).
- Config persistence / saved profiles.
- Polished / themed UI.
```
