package app.yellowvpn.plugin

/** State callback invoked by the Rust engine over JNI. `state` is one of
 *  "connecting" / "established" / "reconnecting" / "disconnected" / "error:<msg>". */
interface StateCallback {
    fun onState(state: String)
}

/**
 * JNI bridge to the Rust VPN engine (`libvpn_engine.so`, built by
 * scripts/build-android-engine.mjs and staged into jniLibs).
 *
 * The native symbol backing [runEngine] is
 * `Java_app_yellowvpn_plugin_VpnBridge_runEngine` in crates/vpn-engine/src/jni_bridge.rs.
 * Keep this class's package (`app.yellowvpn.plugin`) and name (`VpnBridge`) in
 * sync with that symbol.
 */
object VpnBridge {
    init {
        System.loadLibrary("vpn_engine")
    }

    /**
     * Runs the engine against [tunFd] (obtained from VpnService.Builder.establish()).
     * BLOCKS for the tunnel's lifetime, so callers must invoke it on a background
     * thread. State transitions are delivered to [cb].
     */
    external fun runEngine(
        host: String,
        port: Int,
        user: String,
        pass: String,
        tunFd: Int,
        cb: StateCallback,
    )
}
