package app.yellowvpn.plugin

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class ConnectArgs {
    lateinit var host: String
    var port: Int = 443
    var username: String = ""
    var password: String = ""
    var protocol: Int = 0 // 0 = AnyConnect, 1 = Checkpoint
    var insecure: Boolean = false
    var certSha256: String = ""
    var address: String = "10.0.0.2"
    var mtu: Int = 1400
}

/**
 * Tauri mobile plugin bridging the WebView to the Android VpnService. Invoked
 * from JS as `plugin:yellowvpn|connect` / `plugin:yellowvpn|disconnect`. Emits
 * connection-state changes to JS via the `state` plugin event (listen with
 * `addPluginListener('yellowvpn', 'state', cb)`).
 *
 * This lives in Kotlin (not a Rust command) because the VPN consent dialog needs
 * an Activity and there is no reliable Rust->Android bridge in a Tauri app
 * (ndk_context is not initialized by Tauri).
 */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
    private var pending: ConnectArgs? = null

    override fun load(webView: android.webkit.WebView) {
        super.load(webView)
        instance = this
        // Bridge engine state (emitted on the VpnService thread) to the WebView.
        YellowVpnService.stateListener = { s -> emitState(s) }
    }

    @Command
    fun connect(invoke: Invoke) {
        val args = invoke.parseArgs(ConnectArgs::class.java)
        val consent = VpnService.prepare(activity)
        if (consent != null) {
            // Need user consent first; resume in the activity callback.
            pending = args
            startActivityForResult(invoke, consent, "consentResult")
            return
        }
        startTunnel(args)
        invoke.resolve()
    }

    @ActivityCallback
    fun consentResult(invoke: Invoke, result: androidx.activity.result.ActivityResult) {
        val args = pending
        pending = null
        if (result.resultCode == Activity.RESULT_OK && args != null) {
            startTunnel(args)
            invoke.resolve()
        } else {
            invoke.reject("VPN permission denied")
        }
    }

    @Command
    fun disconnect(invoke: Invoke) {
        VpnController.stop(activity)
        invoke.resolve()
    }

    @Command
    fun status(invoke: Invoke) {
        val o = JSObject()
        o.put("state", VpnController.currentState())
        invoke.resolve(o)
    }

    private fun startTunnel(a: ConnectArgs) {
        VpnController.start(
            activity, a.host, a.port, a.username, a.password,
            a.protocol, a.insecure, a.certSha256, a.address, a.mtu,
        )
    }

    private fun emitState(state: String) {
        // trigger() must reach the WebView; marshal off the engine thread.
        activity.runOnUiThread {
            val payload = JSObject()
            payload.put("state", state)
            trigger("state", payload)
        }
    }

    companion object {
        @Volatile
        var instance: VpnPlugin? = null
    }
}
