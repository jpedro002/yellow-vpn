//! Android VPN control: bridges the Tauri `vpn_connect` / `vpn_disconnect`
//! commands to the Kotlin `VpnController` (which owns the `VpnService`) over JNI.
//!
//! The desktop build talks to an elevated helper over a pipe/socket (see
//! `pipe.rs`); Android has no such helper — the engine runs in-process inside the
//! `VpnService`, so these commands just call the Kotlin controller's `@JvmStatic`
//! entry points. The current Android `Context` and `JavaVM` come from
//! `ndk_context`, which Tauri populates at startup.
#![cfg(target_os = "android")]

use jni::objects::{JObject, JValue};

use vpn_ipc::WireConfig;

/// Call `VpnController.startFromNative(ctx, host, port, user, pass, address, mtu)`.
/// Returns the Kotlin-side status string ("started" / "consent-requested").
pub fn connect(config: &WireConfig, password: &str) -> Result<String, String> {
    with_controller(|env, ctx, class| {
        let host = env.new_string(&config.host).map_err(err)?;
        let user = env.new_string(&config.username).map_err(err)?;
        let pass = env.new_string(password).map_err(err)?;
        // A1: address/MTU are placeholders until the session negotiates them;
        // the VpnService.Builder uses these to bring up the interface.
        let address = env.new_string("10.0.0.2").map_err(err)?;

        let ret = env
            .call_static_method(
                class,
                "startFromNative",
                "(Landroid/content/Context;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;",
                &[
                    JValue::from(&ctx),
                    JValue::from(&host),
                    JValue::Int(config.port as i32),
                    JValue::from(&user),
                    JValue::from(&pass),
                    JValue::from(&address),
                    JValue::Int(1400),
                ],
            )
            .map_err(err)?;
        let obj = ret.l().map_err(err)?;
        let s: String = env
            .get_string(&obj.into())
            .map(Into::into)
            .map_err(err)?;
        Ok(s)
    })
}

/// Call `VpnController.stopFromNative(ctx)`.
pub fn disconnect() -> Result<(), String> {
    with_controller(|env, ctx, class| {
        env.call_static_method(
            class,
            "stopFromNative",
            "(Landroid/content/Context;)V",
            &[JValue::from(&ctx)],
        )
        .map_err(err)?;
        Ok(())
    })
}

/// Resolve the JVM + app Context from `ndk_context`, attach the current thread,
/// look up `app.yellowvpn.plugin.VpnController`, and run `f`.
fn with_controller<T>(
    f: impl FnOnce(&mut jni::JNIEnv, JObject, &jni::objects::JClass) -> Result<T, String>,
) -> Result<T, String> {
    let ctx = ndk_context::android_context();
    // SAFETY: the pointers come from ndk_context, populated by the Android
    // runtime / Tauri at startup and valid for the process lifetime.
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(err)?;
    let mut env = vm.attach_current_thread().map_err(err)?;

    let context_obj = unsafe { JObject::from_raw(ctx.context().cast()) };
    let class = env
        .find_class("app/yellowvpn/plugin/VpnController")
        .map_err(err)?;

    f(&mut env, context_obj, &class)
}

fn err<E: std::fmt::Display>(e: E) -> String {
    format!("android VPN JNI error: {e}")
}
