mod pipe;
mod profiles;
mod wintun;

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

/// First-run: make sure wintun.dll is present next to the exe (downloads it on
/// Windows if missing). Returns true if already present, false if downloaded.
#[tauri::command]
async fn ensure_wintun(app: AppHandle) -> Result<bool, String> {
    wintun::ensure(&app).await
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
    /// Name of the profile the current/last connect used, for the notification.
    current_profile: Option<String>,
}

// `WireState` is a foreign type (from vpn-ipc), so we cannot `impl Default for
// WireState` here (orphan rule, E0117). Instead give the local `VpnState` a
// hand-written `Default` that picks the initial "Disconnected" status.
impl Default for VpnState {
    fn default() -> Self {
        Self {
            writer: None,
            reader: None,
            status: WireState::Disconnected,
            current_profile: None,
        }
    }
}

type Shared = Arc<Mutex<VpnState>>;

#[derive(Deserialize)]
struct ConnectArgs {
    config: WireConfig,
    password: String,
    #[serde(rename = "profileName")]
    profile_name: String,
}

#[tauri::command]
async fn vpn_connect(
    app: AppHandle,
    state: State<'_, Shared>,
    args: ConnectArgs,
) -> Result<(), String> {
    // Record which profile this connect is for, so the reader task can name it
    // in the "Connected" notification (works on both the reuse and fresh paths).
    state.lock().await.current_profile = Some(args.profile_name.clone());

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
                        if matches!(s, WireState::Established) {
                            // Connected: notify the user + hide the window to the
                            // tray (the app keeps running in the background).
                            use tauri_plugin_notification::NotificationExt;
                            let name = shared2
                                .lock()
                                .await
                                .current_profile
                                .clone()
                                .unwrap_or_default();
                            let _ = app2
                                .notification()
                                .builder()
                                .title("Yellow VPN")
                                .body(format!("Connected to {name}"))
                                .show();
                            if let Some(w) = app2.get_webview_window("main") {
                                let _ = w.hide();
                            }
                        }
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
        .plugin(tauri_plugin_notification::init())
        .manage::<Shared>(Arc::new(Mutex::new(VpnState::default())))
        .manage(Db::open(&db_path()).expect("failed to open profiles.db"))
        .setup(|app| {
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

            let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let disconnect = MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &disconnect, &quit])?;

            let mut builder = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "disconnect" => {
                        let shared = app.state::<Shared>().inner().clone();
                        tauri::async_runtime::spawn(async move {
                            let mut st = shared.lock().await;
                            if let Some(mut w) = st.writer.take() {
                                let _ = pipe::send_command(&mut w, &ClientCommand::Disconnect).await;
                                st.writer = Some(w);
                            }
                        });
                    }
                    "quit" => {
                        let shared = app.state::<Shared>().inner().clone();
                        let handle = app.clone();
                        tauri::async_runtime::spawn(async move {
                            {
                                let mut st = shared.lock().await;
                                if let Some(mut w) = st.writer.take() {
                                    let _ = pipe::send_command(&mut w, &ClientCommand::Shutdown).await;
                                }
                            }
                            handle.exit(0);
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                builder = builder.icon(icon.clone());
            }
            builder.build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            vpn_status,
            ensure_wintun,
            profiles_list,
            profile_create,
            profile_update,
            profile_delete
        ])
        .on_window_event(|window, event| {
            // Close = hide to tray (Discord-style): the app keeps running in the
            // background and the tunnel + helper stay alive. Real teardown +
            // exit happens only via the tray "Quit" item. This prevents the
            // window's X from killing an active VPN connection.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
