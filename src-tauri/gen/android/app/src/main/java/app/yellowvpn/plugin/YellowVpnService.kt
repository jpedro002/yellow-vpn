package app.yellowvpn.plugin

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlin.concurrent.thread

/**
 * Hosts the Android VPN tunnel. `VpnService.Builder` configures addresses, routes,
 * DNS and MTU (the Rust engine deliberately does none of that on Android); the
 * engine then runs against the fd returned by `establish()`.
 *
 * The service runs in the foreground with a persistent notification — mandatory
 * for a VPN that must survive the app being backgrounded / the screen turning off.
 */
class YellowVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "app.yellowvpn.CONNECT"
        const val ACTION_DISCONNECT = "app.yellowvpn.DISCONNECT"
        private const val TAG = "YellowVpn"
        private const val CHANNEL_ID = "yellow-vpn"
        private const val NOTIFICATION_ID = 1

        /** Latest engine state, readable by the controller / UI bridge. */
        @Volatile
        var lastState: String = "disconnected"
            private set
    }

    private var tun: ParcelFileDescriptor? = null
    @Volatile
    private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            teardown()
            return START_NOT_STICKY
        }

        val host = intent?.getStringExtra("host")
        if (host == null) {
            stopSelf(); return START_NOT_STICKY
        }
        val port = intent.getIntExtra("port", 443)
        val user = intent.getStringExtra("user") ?: ""
        val pass = intent.getStringExtra("pass") ?: ""
        val address = intent.getStringExtra("address") ?: "10.0.0.2"
        val mtu = intent.getIntExtra("mtu", 1400)
        val protocol = intent.getIntExtra("protocol", 0)
        val insecure = intent.getBooleanExtra("insecure", false)
        val certSha256 = intent.getStringExtra("certSha256") ?: ""

        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))

        // VpnService.Builder owns routes/DNS/MTU. A1 uses a full tunnel; split
        // ranges from the server come in A2. addDisallowedApplication excludes our
        // own traffic so the engine's control/data sockets don't loop through the
        // tunnel (A1 stand-in for per-socket protect(); TODO(A2): use protect()).
        val builder = Builder()
            .setSession("Yellow VPN")
            .addAddress(address, 32)
            .addRoute("0.0.0.0", 0)
            .setMtu(mtu)
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "addDisallowedApplication failed: ${e.message}")
        }

        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null")
            teardown(); return START_NOT_STICKY
        }
        tun = pfd
        running = true
        val tunFd = pfd.fd

        thread(name = "yellow-vpn-engine") {
            VpnBridge.runEngine(host, port, user, pass, tunFd, protocol, insecure, certSha256, object : StateCallback {
                override fun onState(state: String) {
                    lastState = state
                    Log.i(TAG, "state=$state")
                    updateNotification(state)
                    // TODO: forward `state` to the Tauri event bus (see VpnController).
                }
            })
            // runEngine returned => tunnel ended.
            if (running) teardown()
        }
        return START_STICKY
    }

    private fun teardown() {
        running = false
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        lastState = "disconnected"
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    override fun onRevoke() {
        // The system or another VPN app revoked our tunnel.
        teardown()
        super.onRevoke()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Yellow VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun buildNotification(text: String): Notification {
        ensureChannel()
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Yellow VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(state: String) {
        val text = when {
            state == "established" -> "Connected"
            state == "connecting" -> "Connecting…"
            state == "reconnecting" -> "Reconnecting…"
            state.startsWith("error:") -> "Error"
            else -> "Disconnected"
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
