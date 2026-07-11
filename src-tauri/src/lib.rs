mod pipe;
mod profiles;

use std::sync::Arc;

use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::Mutex;

use profiles::{Db, NewProfile, Profile};
use vpn_ipc::{ClientCommand, ClientMessage, WireConfig, WireState};

/// Path to the profiles DB: `%APPDATA%\yellow-vpn\profiles.db` (dir created on demand).
fn db_path() -> std::path::PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let dir = std::path::Path::new(&base).join("yellow-vpn");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("profiles.db")
}

#[tauri::command]
async fn profiles_list(db: State<'_, Db>) -> Result<Vec<Profile>, String> {
    db.list().map_err(|e| e.to_string())
}

#[tauri::command]
async fn profile_create(db: State<'_, Db>, profile: NewProfile) -> Result<Profile, String> {
    db.create(&profile).map_err(|e| e.to_string())
}

#[tauri::command]
async fn profile_update(db: State<'_, Db>, id: i64, profile: NewProfile) -> Result<Profile, String> {
    db.update(id, &profile).map_err(|e| e.to_string())
}

#[tauri::command]
async fn profile_delete(db: State<'_, Db>, id: i64) -> Result<(), String> {
    db.delete(id).map_err(|e| e.to_string())
}

struct VpnState {
    writer: Option<tokio::io::WriteHalf<NamedPipeClient>>,
    reader: Option<tokio::task::JoinHandle<()>>,
    status: WireState,
}

// `WireState` is a foreign type (from vpn-ipc), so we cannot `impl Default for
// WireState` here (orphan rule, E0117). Instead give the local `VpnState` a
// hand-written `Default` that picks the initial "Disconnected" status.
impl Default for VpnState {
    fn default() -> Self {
        Self { writer: None, reader: None, status: WireState::Disconnected }
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
    // The elevated helper serves exactly one pipe connection for its whole
    // lifetime (create -> connect -> serve; EOF on that pipe makes the
    // helper process exit). So a healthy existing connection must be
    // *reused*, never torn down, across connect/disconnect/reconnect: the
    // helper's own `handle_connect` already stops any prior tunnel and
    // swaps to the new one, and it stays alive across `Disconnect`. Dropping
    // the writer here would close the pipe, kill the helper, and force a
    // fresh UAC prompt (plus a race against the dying old helper for the
    // pipe name) on the very next connect.
    //
    // First, try to reuse a live writer. The lock is held only long enough
    // to take the writer out, not across the `.await` on the pipe write.
    let existing = { state.lock().await.writer.take() };

    if let Some(mut w) = existing {
        let cmd = ClientCommand::Connect {
            config: args.config.clone(),
            password: args.password.clone(),
        };
        if pipe::send_command(&mut w, &cmd).await.is_ok() {
            // Pipe is alive and the helper is swapping tunnels under it.
            // The existing long-lived reader task keeps relaying; no new
            // reader is spawned.
            state.lock().await.writer = Some(w);
            return Ok(());
        }
        // Pipe is dead (helper crashed/exited): abort the now-stale reader
        // and fall through to a fresh connect below.
        if let Some(r) = state.lock().await.reader.take() {
            r.abort();
        }
        drop(w);
    }

    // Fresh-connect path: no live writer existed, or reuse above failed.
    let client = pipe::connect_with_spawn().await.map_err(|e| e.to_string())?;
    let (mut writer, mut lines) = pipe::split(client);

    // Send the Connect command on the local `writer` binding directly (no
    // take()/unwrap() round-trip through the shared state), then store the
    // writer into state only once it has proven usable.
    pipe::send_command(
        &mut writer,
        &ClientCommand::Connect { config: args.config, password: args.password },
    )
    .await
    .map_err(|e| e.to_string())?;

    // Relay helper messages to the frontend + track status. This reader
    // task lives for as long as the pipe connection does (i.e. for the
    // life of the helper process), spanning multiple connect/disconnect
    // cycles -- it is not re-spawned on the reuse path above.
    let app2 = app.clone();
    let shared2: Shared = state.inner().clone();
    let reader = tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(msg) = serde_json::from_str::<ClientMessage>(&line) {
                match &msg {
                    ClientMessage::State(s) => {
                        shared2.lock().await.status = s.clone();
                    }
                    ClientMessage::Error { permanent: true, .. } => {
                        // The engine will not retry: the tunnel is down, so
                        // stop reporting a stale Connecting/Established
                        // status. (Transient errors leave status alone --
                        // a retry/reconnect attempt is still in flight.)
                        shared2.lock().await.status = WireState::Disconnected;
                    }
                    _ => {}
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

    {
        let mut st = state.lock().await;
        st.writer = Some(writer);
        st.reader = Some(reader);
    }

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
        .manage(Db::open(&db_path()).expect("failed to open profiles.db"))
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            vpn_status,
            profiles_list,
            profile_create,
            profile_update,
            profile_delete
        ])
        .on_window_event(|window, event| {
            // On close, tell the helper to shut down so no tunnel is orphaned.
            // We use a best-effort fire-and-forget spawn rather than
            // `tauri::async_runtime::block_on` here: blocking synchronously
            // inside the window-event callback risks deadlocking against the
            // async runtime that also drives this same Mutex (the reader task
            // spawned in `vpn_connect` locks `shared2` from within the async
            // executor), and there is no bound on how long a hung pipe write
            // could stall window teardown. A spawned task sends the Shutdown
            // command without blocking the event handler; if the process exits
            // before it lands, the helper's own EOF-on-pipe-close handling
            // (see vpn-helper's `serve()`) already guarantees the tunnel is
            // torn down.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state: State<'_, Shared> = window.state();
                let shared = state.inner().clone();
                tauri::async_runtime::spawn(async move {
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
