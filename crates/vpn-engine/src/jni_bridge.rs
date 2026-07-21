//! JNI export consumed by the Kotlin `VpnService` plugin. Kotlin passes the
//! connection config (host/port/user/password) and the TUN fd it obtained from
//! `VpnService.Builder.establish()`, and receives connection-state callbacks.
//!
//! This is a single BLOCKING call that owns a current-thread tokio runtime for
//! the connection's lifetime; the Kotlin side runs it on a dedicated background
//! thread. A current-thread runtime is required because `JNIEnv` is `!Send`: on
//! a multi-thread runtime the state-pump future (which touches JNI) could not
//! be scheduled. State is delivered by re-attaching the current thread to the JVM
//! for each event and invoking the callback's `onState(String)` method.
#![cfg(target_os = "android")]

use std::sync::Mutex;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint};
use jni::{JNIEnv, JavaVM};

use crate::client::{run_client_supervised_android, ClientEvent};
use crate::config::{Config, Protocol};

/// Shutdown handle for the CURRENTLY running tunnel. Only one tunnel runs at a
/// time; starting a new one signals the previous to stop first, and `stopEngine`
/// (called from Kotlin on disconnect/teardown) flips it to end the tunnel.
static ENGINE_SHUTDOWN: Mutex<Option<tokio::sync::watch::Sender<bool>>> = Mutex::new(None);

/// Parse a hex SHA-256 fingerprint (optionally colon-separated) into 32 bytes.
fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let hex: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Called by Kotlin:
/// `external fun runEngine(host, port, user, pass, tunFd, cb: StateCallback)`.
/// Blocks until the tunnel ends (clean disconnect or permanent error). State
/// strings — "connecting" / "established" / "reconnecting" / "disconnected" /
/// "error:<msg>" — are delivered to `cb.onState(String)`.
///
/// The symbol name MUST match the Kotlin package + class:
/// `app.yellowvpn.plugin.VpnBridge`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_yellowvpn_plugin_VpnBridge_runEngine(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jint,
    user: JString,
    pass: JString,
    protocol: jint,
    insecure: jboolean,
    cert_sha256: JString,
    tun_builder: JObject,
    callback: JObject,
) {
    // Engine logs go to stderr, which Android surfaces in logcat under the
    // RustStdoutStderr tag. try_init so repeated connects don't panic.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .try_init();

    let host: String = env.get_string(&host).map(Into::into).unwrap_or_default();
    let user: String = env.get_string(&user).map(Into::into).unwrap_or_default();
    let pass: String = env.get_string(&pass).map(Into::into).unwrap_or_default();
    let cert: String = env
        .get_string(&cert_sha256)
        .map(Into::into)
        .unwrap_or_default();

    // Hold a JVM handle + a global ref to the callback so we can re-attach the
    // thread and invoke the callback across await points (JNIEnv itself is !Send
    // and its lifetime is tied to this frame, so we cannot keep it around).
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            tracing::error!("android: get_java_vm failed: {e}");
            return;
        }
    };
    let cb_global = match env.new_global_ref(&callback) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("android: new_global_ref(callback) failed: {e}");
            return;
        }
    };
    // Second JVM handle + global ref for the TUN builder callback, used post-
    // handshake to establish the VpnService tunnel with the SERVER-ASSIGNED
    // address/DNS (the fd must not be created before we know them).
    let vm_tun = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            tracing::error!("android: get_java_vm (tun) failed: {e}");
            return;
        }
    };
    let tun_global = match env.new_global_ref(&tun_builder) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("android: new_global_ref(tun_builder) failed: {e}");
            return;
        }
    };
    // Factory the engine calls once it knows the session address: build the tun on
    // the Kotlin side and hand back the fd. Called on the engine (block_on) thread.
    let tun_factory: crate::client::AndroidTunFactory = Box::new(
        move |params: &crate::tunnel::SessionParams| -> Result<std::os::fd::RawFd, crate::error::VpnError> {
            let mut env = vm_tun
                .attach_current_thread()
                .map_err(|e| crate::error::VpnError::Tun(format!("attach for tun builder: {e}")))?;
            let addr = env
                .new_string(params.address.to_string())
                .map_err(|e| crate::error::VpnError::Tun(e.to_string()))?;
            let dns = params
                .dns
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let jdns = env
                .new_string(dns)
                .map_err(|e| crate::error::VpnError::Tun(e.to_string()))?;
            let fd = env
                .call_method(
                    tun_global.as_obj(),
                    "configure",
                    "(Ljava/lang/String;ILjava/lang/String;)I",
                    &[
                        JValue::from(&addr),
                        JValue::Int(params.mtu as i32),
                        JValue::from(&jdns),
                    ],
                )
                .and_then(|v| v.i())
                .map_err(|e| crate::error::VpnError::Tun(format!("tun configure call: {e}")))?;
            if fd < 0 {
                return Err(crate::error::VpnError::Tun(
                    "VpnService.Builder.establish() failed (fd < 0)".into(),
                ));
            }
            Ok(fd as std::os::fd::RawFd)
        },
    );

    let config = Config {
        host,
        port: port as u16,
        username: user,
        password: None, // password is passed separately to the run entry
        verbose: false,
        cert_sha256: if cert.trim().is_empty() {
            None
        } else {
            parse_fingerprint(&cert)
        },
        insecure: insecure != 0,
        protocol: match protocol {
            1 => Protocol::Checkpoint,
            2 => Protocol::FortiGate,
            _ => Protocol::AnyConnect,
        },
    };

    // Current-thread runtime: keeps every future (incl. the JNI state pump) on
    // this one OS thread, satisfying JNIEnv's !Send constraint.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            emit_state(&vm, &cb_global, &format!("error:{e}"));
            return;
        }
    };

    // Stop any previous tunnel before starting this one — otherwise a second
    // connect spawns a competing engine that fights over the TUN (endless
    // reconnect war). Register this run's shutdown handle so disconnect works.
    if let Ok(mut guard) = ENGINE_SHUTDOWN.lock() {
        if let Some(old) = guard.take() {
            let _ = old.send(true);
        }
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    if let Ok(mut guard) = ENGINE_SHUTDOWN.lock() {
        *guard = Some(shutdown_tx);
    }
    let (etx, mut erx) = tokio::sync::mpsc::channel::<ClientEvent>(16);

    rt.block_on(async move {
        let pump = async {
            while let Some(ev) = erx.recv().await {
                let s = match ev {
                    ClientEvent::Connecting => "connecting".to_string(),
                    ClientEvent::Established => "established".to_string(),
                    ClientEvent::Reconnecting { .. } => "reconnecting".to_string(),
                    ClientEvent::Disconnected => "disconnected".to_string(),
                    ClientEvent::PermanentError(msg) => format!("error:{msg}"),
                };
                emit_state(&vm, &cb_global, &s);
            }
        };
        let run =
            run_client_supervised_android(&config, &pass, tun_factory, shutdown_rx, etx);

        tokio::pin!(pump);
        let res = tokio::select! {
            r = run => r,
            _ = &mut pump => Ok(()),
        };
        // Drain any remaining events (e.g. the terminal Disconnected) after run ends.
        pump.await;
        if let Err(e) = res {
            emit_state(&vm, &cb_global, &format!("error:{e}"));
        }
    });
}

/// Called by Kotlin on disconnect/teardown: signal the running tunnel to stop.
/// Idempotent — no-op if nothing is running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_yellowvpn_plugin_VpnBridge_stopEngine(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Ok(mut guard) = ENGINE_SHUTDOWN.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(true);
        }
    }
}

/// Re-attach the current thread to the JVM and invoke `callback.onState(state)`.
/// Best-effort: logs and returns on any JNI error rather than unwinding across
/// the FFI boundary.
fn emit_state(vm: &JavaVM, callback: &GlobalRef, state: &str) {
    let mut env = match vm.attach_current_thread() {
        Ok(guard) => guard,
        Err(e) => {
            tracing::error!("android: attach_current_thread failed: {e}");
            return;
        }
    };
    let jstr = match env.new_string(state) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("android: new_string failed: {e}");
            return;
        }
    };
    if let Err(e) = env.call_method(
        callback.as_obj(),
        "onState",
        "(Ljava/lang/String;)V",
        &[JValue::from(&jstr)],
    ) {
        tracing::error!("android: onState callback failed: {e}");
    }
}
