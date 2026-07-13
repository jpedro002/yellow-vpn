//! Elevated helper: owns the VPN engine, serves the GUI over a local transport.
//!
//! Transport is per-OS but the serving logic is shared:
//!   * Windows — a restricted named pipe (`\\.\pipe\yellow-vpn`).
//!   * macOS/Linux — a Unix-domain socket (`/var/run/yellow-vpn/helper.sock`).
//!
//! In both cases the helper runs elevated (Administrator / root), owns the VPN
//! engine, and speaks newline-delimited JSON (`vpn-ipc`) to the GUI.

/// Transport-agnostic protocol: everything that does not depend on how the
/// GUI connection was established. Both the Windows and Unix backends set up
/// their stream, split it, and hand the halves to [`proto::serve`].
mod proto {
    use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
    use tokio::sync::{mpsc, watch, Mutex};

    use vpn_engine::config::{parse_sha256_fingerprint, Config, Protocol};
    use vpn_engine::{platform, run_client_supervised, ClientEvent};
    use vpn_ipc::{ClientCommand, ClientMessage, WireConfig, WireProtocol, WireState};

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

    /// Shared writer handle over any async write half.
    type Writer<W> = Arc<Mutex<W>>;

    async fn send<W: AsyncWrite + Unpin>(writer: &Writer<W>, msg: &ClientMessage) {
        if let Ok(mut line) = serde_json::to_string(msg) {
            line.push('\n');
            let mut w = writer.lock().await;
            let _ = w.write_all(line.as_bytes()).await;
            let _ = w.flush().await;
        }
    }

    /// Handle one Connect: pre-flight checks, then spawn the supervised engine and
    /// a task that forwards its events to the transport.
    async fn handle_connect<W>(session: &Arc<Mutex<Session>>, writer: &Writer<W>, config: Config)
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
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
        // forwarding task (transport write backpressure) doesn't block the engine's
        // event.send() calls on its hot path.
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

    /// Serve one GUI connection until it closes or asks to shut down.
    pub async fn serve<R, W>(read_half: R, write_half: W)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let writer: Writer<W> = Arc::new(Mutex::new(write_half));
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
                // EOF: the GUI closed the connection. Never leave a tunnel up.
                Ok(None) => {
                    tracing::info!("connection closed by client — shutting down");
                    session.lock().await.stop().await;
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "transport read error — shutting down");
                    session.lock().await.stop().await;
                    break;
                }
            }
        }
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
}

#[cfg(windows)]
mod windows_impl {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use vpn_ipc::PIPE_NAME;

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
            // GetTokenInformation(TokenUser), so it holds a valid TOKEN_USER.
            // `buf` is a `Vec<u8>` (alignment 1), so we must NOT form a
            // `&TOKEN_USER` reference to it (that would be under-aligned UB);
            // read the struct out with `read_unaligned` into an owned, aligned
            // copy instead. `token_user.User.Sid` points inside `buf` and stays
            // valid as long as `buf` is alive (it is, for the rest of this block).
            let token_user = std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_USER);
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
        let (read_half, write_half) = tokio::io::split(server);
        super::proto::serve(read_half, write_half).await;
        tracing::info!("helper exiting");
    }
}

#[cfg(unix)]
mod unix_impl {
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    use nix::unistd::{chown, Uid};
    use tokio::net::UnixListener;
    use vpn_ipc::{SOCKET_DIR, SOCKET_PATH};

    /// Directory for helper logs. Created root-owned mode 0700 so no other user
    /// can pre-plant a symlink at the log path (the /tmp symlink-attack class).
    const LOG_DIR: &str = "/var/log/yellow-vpn";

    /// Create `dir` (if absent) owned by root with `mode`, and verify the final
    /// path is a real directory — NOT a symlink an attacker planted. Fails closed.
    fn ensure_root_dir(dir: &str, mode: u32) -> io::Result<()> {
        match std::fs::DirBuilder::new().mode(mode).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        // symlink_metadata does not follow: reject if the path is a symlink.
        let md = std::fs::symlink_metadata(dir)?;
        if !md.is_dir() {
            return Err(io::Error::other(format!("{dir} is not a real directory")));
        }
        // Re-assert ownership+mode in case the dir pre-existed with weaker perms.
        chown(dir, Some(Uid::from_raw(0)), None).map_err(io::Error::other)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn init_log() {
        if ensure_root_dir(LOG_DIR, 0o700).is_err() {
            return; // No safe place to log; run without a log file.
        }
        let path = Path::new(LOG_DIR).join("helper.log");
        // O_NOFOLLOW: refuse to open through a symlink. Combined with the
        // root-only (0700) directory this closes the symlink-attack vector.
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path);
        if let Ok(file) = opened {
            let _ = tracing_subscriber::fmt().with_writer(std::sync::Mutex::new(file)).try_init();
        }
    }

    /// Parse the interactive user's uid from argv[1] (passed by the GUI when it
    /// spawns the helper elevated). The socket is locked to this uid.
    fn owner_uid() -> Option<Uid> {
        std::env::args().nth(1)?.parse::<u32>().ok().map(Uid::from_raw)
    }

    #[tokio::main]
    pub async fn main() {
        init_log();

        let Some(uid) = owner_uid() else {
            tracing::error!("missing owner uid argument — refusing to start");
            return;
        };

        // Socket lives in a root-owned, traverse-only (0711) directory so no
        // other user can create files/symlinks beside it. Non-root users can
        // traverse to reach the socket but cannot write into the directory.
        if let Err(e) = ensure_root_dir(SOCKET_DIR, 0o711) {
            tracing::error!(error = %e, "failed to prepare socket directory");
            return;
        }

        tracing::info!("helper starting; binding socket {SOCKET_PATH}");
        // Clear a stale socket from a prior crash. Safe: the parent dir is now
        // root-owned 0711, so no other user could have substituted this path.
        let _ = std::fs::remove_file(SOCKET_PATH);

        // Bind under umask 0177 so the socket is created mode 0600 from the
        // very first instant — without this there is a window between bind()
        // and the chmod below where any local user could connect() and win
        // the single-connection accept race against the real GUI.
        let prev_umask =
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o177));
        let bind_result = UnixListener::bind(SOCKET_PATH);
        nix::sys::stat::umask(prev_umask);
        let listener = match bind_result {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "failed to bind socket");
                return;
            }
        };

        // Lock the socket to the interactive user: chown to their uid + mode
        // 0600 so ONLY that uid (and root) may connect(). This is the Unix
        // equivalent of the Windows restricted-DACL pipe.
        if let Err(e) = chown(SOCKET_PATH, Some(uid), None) {
            tracing::error!(error = %e, "failed to chown socket — refusing to serve");
            let _ = std::fs::remove_file(SOCKET_PATH);
            return;
        }
        if let Err(e) =
            std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))
        {
            tracing::error!(error = %e, "failed to set socket mode — refusing to serve");
            let _ = std::fs::remove_file(SOCKET_PATH);
            return;
        }

        // Accept until the peer is the expected user. File permissions already
        // gate connect(), but this defends in depth: peer credentials come
        // from the kernel and can't be raced the way path perms can.
        let stream = loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!(error = %e, "socket accept failed");
                    let _ = std::fs::remove_file(SOCKET_PATH);
                    return;
                }
            };
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == uid.as_raw() || cred.uid() == 0 => break stream,
                Ok(cred) => {
                    tracing::warn!(peer_uid = cred.uid(), "rejected connection from unauthorized uid");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not read peer credentials — rejected connection");
                }
            }
        };
        tracing::info!("GUI connected");

        let (read_half, write_half) = tokio::io::split(stream);
        super::proto::serve(read_half, write_half).await;

        // Clean up so the next launch binds fresh.
        let _ = std::fs::remove_file(SOCKET_PATH);
        tracing::info!("helper exiting");
    }
}

#[cfg(windows)]
fn main() {
    windows_impl::main()
}

#[cfg(unix)]
fn main() {
    unix_impl::main()
}
