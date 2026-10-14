package app.yellowvpn.plugin

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
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
    var newPassword: String = ""
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
        // Ask for notification permission at startup so the foreground-service
        // notification is already allowed by the time the user hits connect (asking
        // on first connect races the service start and misses the first tunnel).
        ensureNotificationPermission()
        // Bridge engine state (emitted on the VpnService thread) to the WebView.
        YellowVpnService.stateListener = { s -> emitState(s) }
    }

    /** On API 33+ the foreground-service notification is hidden unless the user
     *  granted POST_NOTIFICATIONS. Ask once, best-effort — never block the connect
     *  on the result (the tunnel works regardless; only the notification depends
     *  on it). */
    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED
        ) return
        activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
    }

    @Command
    fun connect(invoke: Invoke) {
        val args = invoke.parseArgs(ConnectArgs::class.java)
        ensureNotificationPermission()
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

    /** Password-rotation notices for the UI poll. Each field is consume-once, so a
     *  prompt is delivered a single time. */
    @Command
    fun notice(invoke: Invoke) {
        val o = JSObject()
        o.put("passwordExpired", VpnController.takePasswordExpired())
        o.put("passwordChanged", VpnController.takePasswordChanged())
        invoke.resolve(o)
    }

    private fun startTunnel(a: ConnectArgs) {
        VpnController.start(
            activity, a.host, a.port, a.username, a.password,
            a.protocol, a.insecure, a.certSha256, a.address, a.mtu,
            newPass = a.newPassword,
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
        private const val REQ_NOTIF = 0x7602
        @Volatile
        var instance: VpnPlugin? = null
    }
}
