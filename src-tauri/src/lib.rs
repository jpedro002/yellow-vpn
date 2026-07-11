mod pipe;

use std::sync::Arc;

use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::Mutex;

use vpn_ipc::{ClientCommand, ClientMessage, WireConfig, WireState};

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
    // Tear down any prior connection before starting a new one: if
    // `vpn_connect` is called again while a previous connection is live
    // (double-click, or reconnect after an error without a clean
    // disconnect), the old writer must be dropped so the old pipe closes,
    // and the old reader task must be aborted so it does not keep racing
    // the new one on `status` / `vpn://state`. The lock is released before
    // the `.await` on `connect_with_spawn` below so we don't hold it across
    // the connect+UAC wait.
    {
        let mut st = state.lock().await;
        st.writer.take();
        if let Some(old_reader) = st.reader.take() {
            old_reader.abort();
        }
    }

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

    // Relay helper messages to the frontend + track status.
    let app2 = app.clone();
    let shared2: Shared = state.inner().clone();
    let reader = tokio::spawn(async move {
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
        .invoke_handler(tauri::generate_handler![vpn_connect, vpn_disconnect, vpn_status])
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
