//! Elevated helper: owns the VPN engine, serves the GUI over a named pipe.
//!
//! This binary is Windows-only (it talks to the GUI over a Windows named pipe
//! and drives Windows-specific privilege/TUN checks). On other platforms it
//! compiles to a no-op so `cargo build --workspace` stays green everywhere.

#[cfg(windows)]
mod windows_impl {
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

    /// Holds the shutdown handle and engine task for whatever tunnel is currently running.
    #[derive(Default)]
    struct Session {
        shutdown: Option<watch::Sender<bool>>,
        engine: Option<tokio::task::JoinHandle<()>>,
    }

    impl Session {
        /// Flip shutdown on any running tunnel and await its teardown (bounded), so
        /// routes are removed before we consider the tunnel stopped.
        async fn stop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(true);
            }
            if let Some(handle) = self.engine.take() {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(10), handle).await;
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
        // Stop any prior tunnel first (and wait for its teardown to finish).
        session.lock().await.stop().await;

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

        let engine_handle = tokio::spawn(async move {
            let pw = config.password.clone().unwrap_or_default();
            let _ = run_client_supervised(&config, &pw, shutdown_rx, etx).await;
        });
        session.lock().await.engine = Some(engine_handle);
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
                            session.lock().await.stop().await;
                        }
                        ClientCommand::Shutdown => {
                            session.lock().await.stop().await;
                            send(&writer, &ClientMessage::Bye).await;
                            break;
                        }
                    }
                }
                // EOF: the GUI closed the pipe. Never leave a tunnel up.
                Ok(None) => {
                    tracing::info!("pipe closed by client — shutting down");
                    session.lock().await.stop().await;
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "pipe read error — shutting down");
                    session.lock().await.stop().await;
                    break;
                }
            }
        }
    }

    /// Failure modes for [`create_restricted_pipe`], kept distinct so `main` can
    /// fall back to an unrestricted pipe only when the *descriptor* couldn't be
    /// built — a genuine pipe-creation failure (e.g. another helper already owns
    /// the name) should still be reported as a hard error, not silently retried
    /// with a weaker ACL.
    enum PipeCreateError {
        SdBuild(std::io::Error),
        Create(std::io::Error),
    }

    /// Look up the SID of the current process token, formatted as a string (e.g.
    /// `S-1-5-21-...`), for use in the pipe's SDDL security descriptor.
    ///
    /// Safety/resource notes: the process token handle is opened with
    /// `TOKEN_QUERY` and closed on every exit path. `GetTokenInformation` is
    /// called twice (two-call pattern): first with a null/zero buffer purely to
    /// learn the required size (its own failure there is expected and ignored;
    /// only the returned size matters), then again into a heap buffer sized to
    /// match. The `TOKEN_USER.User.Sid` pointer borrowed from that buffer is only
    /// read while the buffer is alive. `ConvertSidToStringSidW` allocates its
    /// output with `LocalAlloc` internally; we measure the NUL-terminated wide
    /// string, copy it into an owned `String`, then free it with `LocalFree`
    /// before returning.
    fn current_user_sid_string() -> std::io::Result<String> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            // First call: ask for the required buffer size. This is expected to
            // report failure (ERROR_INSUFFICIENT_BUFFER) while still filling in
            // `needed`; only `needed` is used below.
            let mut needed: u32 = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                let e = std::io::Error::last_os_error();
                CloseHandle(token);
                return Err(e);
            }

            let mut buf = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                needed,
                &mut needed,
            );
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                CloseHandle(token);
                return Err(e);
            }

            // Safety: `buf` was sized to `needed` and just filled by
            // GetTokenInformation(TokenUser), so it holds a valid TOKEN_USER;
            // `token_user.User.Sid` points inside `buf` and is valid as long as
            // `buf` is alive (it is, for the rest of this block).
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;

            let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSidToStringSidW(sid, &mut sid_str_ptr);
            CloseHandle(token);
            if ok == 0 || sid_str_ptr.is_null() {
                return Err(std::io::Error::last_os_error());
            }

            let mut len = 0usize;
            while *sid_str_ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(sid_str_ptr, len);
            let sid_string = String::from_utf16_lossy(slice);
            LocalFree(sid_str_ptr as HLOCAL);
            Ok(sid_string)
        }
    }

    /// Create the control pipe with a security descriptor that grants
    /// `GENERIC_ALL` only to the current user, Built-in Administrators (`BA`),
    /// and Local System (`SY`) — a protected DACL (`D:P`, no inherited or
    /// default ACEs) so no other user on the machine can open the pipe. This is
    /// what lets the unprivileged GUI (same interactive user, medium integrity)
    /// talk to the elevated helper while keeping other users locked out.
    fn create_restricted_pipe() -> Result<NamedPipeServer, PipeCreateError> {
        use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

        let sid_string = current_user_sid_string().map_err(PipeCreateError::SdBuild)?;
        // D:P = protected DACL (ignore inherited/default ACEs). Three allow ACEs:
        // SYSTEM, Administrators, and the current user, each GENERIC_ALL.
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid_string})");
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // Safety: `sddl_wide` is a NUL-terminated wide string alive for this call;
        // `psd` receives a self-relative security descriptor allocated by the OS
        // (via LocalAlloc) that we own and must LocalFree once done with it.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || psd.is_null() {
            return Err(PipeCreateError::SdBuild(std::io::Error::last_os_error()));
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };

        // Safety: `sa` is a fully-initialized SECURITY_ATTRIBUTES pointing at the
        // self-relative descriptor built above, and both stay alive across this
        // call. CreateNamedPipeW (which this wraps) copies the descriptor into
        // the kernel object rather than retaining our pointer, so it's safe to
        // free `psd` immediately after this call returns, on either outcome.
        let result = unsafe {
            ServerOptions::new().first_pipe_instance(true).create_with_security_attributes_raw(
                PIPE_NAME,
                &mut sa as *mut _ as *mut core::ffi::c_void,
            )
        };

        unsafe { LocalFree(psd as HLOCAL) };

        result.map_err(PipeCreateError::Create)
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
    pub async fn main() {
        init_log();
        tracing::info!("helper starting; creating pipe {PIPE_NAME}");
        // First instance owns the pipe; create then wait for the GUI to connect.
        // The happy path restricts the pipe's DACL to the current user + Admins +
        // SYSTEM (see `create_restricted_pipe`). If building that descriptor fails
        // (SD-construction FFI step), fall back to a plain pipe so the app still
        // functions rather than refusing to start; an actual pipe-creation
        // failure (e.g. another helper instance already owns the name) is still
        // a hard error either way.
        let server = match create_restricted_pipe() {
            Ok(s) => s,
            Err(PipeCreateError::SdBuild(e)) => {
                tracing::warn!(
                    error = %e,
                    "could not build restrictive pipe security descriptor — \
                     falling back to default pipe ACL"
                );
                match ServerOptions::new().first_pipe_instance(true).create(PIPE_NAME) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to create pipe — another helper running?");
                        return;
                    }
                }
            }
            Err(PipeCreateError::Create(e)) => {
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
}

#[cfg(windows)]
fn main() {
    windows_impl::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("yellow-vpn-helper is Windows-only");
    std::process::exit(1);
}
