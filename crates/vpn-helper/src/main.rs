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

    // Larger buffer than the engine's own internal default so a momentary stall in the
    // forwarding task (pipe write backpressure) doesn't block the engine's event.send()
    // calls on its hot path (Task 3 review note).
    let (etx, mut erx) = mpsc::channel::<ClientEvent>(128);
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
