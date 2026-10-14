package app.yellowvpn.plugin

/** State callback invoked by the Rust engine over JNI. `state` is one of
 *  "connecting" / "established" / "reconnecting" / "disconnected" / "error:<msg>" /
 *  "password_expired:<prompt>" / "password_changed". */
interface StateCallback {
    fun onState(state: String)
}

/**
 * Called by the engine AFTER the handshake, once the server-assigned tunnel
 * address/DNS are known, to establish the VpnService tunnel. Returns the TUN file
 * descriptor (or a negative value on failure). `dns` is a comma-separated list.
 */
interface TunBuilder {
    fun configure(address: String, mtu: Int, dns: String): Int
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
        newPass: String, // replacement for an expired password, empty for none
        protocol: Int, // 0 = AnyConnect, 1 = Checkpoint
        insecure: Boolean,
        certSha256: String, // hex SHA-256 fingerprint, empty for none
        tunBuilder: TunBuilder,
        cb: StateCallback,
    )

    /** Signal the running tunnel to stop (disconnect / teardown). No-op if idle. */
    external fun stopEngine()
}
