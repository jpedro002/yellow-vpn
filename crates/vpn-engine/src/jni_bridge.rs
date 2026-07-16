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

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint};
use jni::{JNIEnv, JavaVM};

use crate::client::{run_client_supervised_android, ClientEvent};
use crate::config::{Config, Protocol};

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
    tun_fd: jint,
    protocol: jint,
    insecure: jboolean,
    cert_sha256: JString,
    callback: JObject,
) {
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

    // A1 has no external disconnect wire yet (that is A2); the tunnel runs until
    // it ends on its own (permanent error) or the service tears down the fd.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
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
            run_client_supervised_android(&config, &pass, tun_fd as std::os::fd::RawFd, shutdown_rx, etx);

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
