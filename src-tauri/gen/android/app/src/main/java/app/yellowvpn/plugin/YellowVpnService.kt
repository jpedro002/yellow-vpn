package app.yellowvpn.plugin

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
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

        /** Set by VpnPlugin to forward engine state to the WebView. */
        @Volatile
        var stateListener: ((String) -> Unit)? = null

        // Password-rotation notices are sticky and separate from lastState: the engine
        // ends right after "password_expired", teardown() resets lastState to
        // "disconnected", and the UI only polls — it would never see the prompt.
        @Volatile
        private var passwordExpiredPrompt: String? = null
        @Volatile
        private var passwordChanged = false

        fun takePasswordExpired(): String? {
            val p = passwordExpiredPrompt
            passwordExpiredPrompt = null
            return p
        }

        fun takePasswordChanged(): Boolean {
            val c = passwordChanged
            passwordChanged = false
            return c
        }
    }

    private var tun: ParcelFileDescriptor? = null
    // Host of the active tunnel, shown as the notification subtitle.
    @Volatile
    private var host: String = ""
    // SystemClock.elapsedRealtime() when the tunnel reached "established", so the
    // notification can run a live "connected for HH:MM" chronometer (Waze-style).
    @Volatile
    private var connectedSince: Long = 0L
    @Volatile
    private var running = false
    // Bumped on every connect. A finishing engine thread only tears the service
    // down if it is still the current generation, so a replaced tunnel's thread
    // can't kill the new one.
    @Volatile
    private var generation = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            teardown()
            return START_NOT_STICKY
        }

        val host = intent?.getStringExtra("host")
        if (host == null) {
            stopSelf(); return START_NOT_STICKY
        }
        this.host = host
        val port = intent.getIntExtra("port", 443)
        val user = intent.getStringExtra("user") ?: ""
        val pass = intent.getStringExtra("pass") ?: ""
        val newPass = intent.getStringExtra("newPass") ?: ""
        val protocol = intent.getIntExtra("protocol", 0)
        val insecure = intent.getBooleanExtra("insecure", false)
        val certSha256 = intent.getStringExtra("certSha256") ?: ""

        connectedSince = 0L
        // A fresh attempt supersedes any unread notice from the previous one.
        passwordExpiredPrompt = null
        passwordChanged = false
        // On API 34+ a service declared foregroundServiceType="specialUse" MUST pass
        // the type at runtime, otherwise the FGS starts "without any types" and the
        // notification is not displayed. Pre-34 uses the 2-arg overload.
        val notif = buildNotification("Connecting…", false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notif)
        }

        // Replace any running tunnel: stop the old engine and close its fd before
        // establishing a new one, so we never run two engines fighting over the TUN.
        if (running) {
            VpnBridge.stopEngine()
            try { tun?.close() } catch (_: Exception) {}
            tun = null
        }

        running = true
        val myGen = ++generation

        thread(name = "yellow-vpn-engine") {
            // The engine establishes the tunnel via this callback AFTER the
            // handshake, so the TUN gets the SERVER-ASSIGNED address (not a guess).
            val tunBuilder = object : TunBuilder {
                override fun configure(address: String, mtu: Int, dns: String): Int {
                    if (generation != myGen) return -1
                    return establishTunnel(address, mtu, dns)
                }
            }
            VpnBridge.runEngine(host, port, user, pass, newPass, protocol, insecure, certSha256, tunBuilder, object : StateCallback {
                override fun onState(state: String) {
                    // Ignore late events from a superseded engine.
                    if (generation != myGen) return
                    // Rotation notices are not connection states: record them for the
                    // UI poll and leave lastState / the notification untouched.
                    if (state.startsWith("password_expired:")) {
                        passwordExpiredPrompt = state.removePrefix("password_expired:")
                        return
                    }
                    if (state == "password_changed") {
                        passwordChanged = true
                        return
                    }
                    lastState = state
                    if (state == "established" && connectedSince == 0L) {
                        connectedSince = SystemClock.elapsedRealtime()
                    } else if (state != "established") {
                        connectedSince = 0L
                    }
                    Log.i(TAG, "state=$state")
                    updateNotification(state)
                    stateListener?.invoke(state)
                }
            })
            // runEngine returned => tunnel ended. Only tear the service down if we
            // are still the current tunnel (a replacement bumps the generation).
            if (generation == myGen && running) teardown()
        }
        return START_STICKY
    }

    /** Build + establish the VpnService tunnel with the server-assigned address.
     *  Full tunnel (0.0.0.0/0); our own app is excluded so the engine's control/
     *  data sockets don't loop (A1 stand-in for per-socket protect()). Returns the
     *  TUN fd, or -1 on failure. */
    private fun establishTunnel(address: String, mtu: Int, dns: String): Int {
        val builder = Builder()
            .setSession("Yellow VPN")
            .addAddress(address, 32)
            .addRoute("0.0.0.0", 0)
            .setMtu(if (mtu in 576..1500) mtu else 1400)
        for (server in dns.split(",")) {
            val d = server.trim()
            if (d.isNotEmpty()) {
                try { builder.addDnsServer(d) } catch (e: Exception) {
                    Log.w(TAG, "addDnsServer($d) failed: ${e.message}")
                }
            }
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "addDisallowedApplication failed: ${e.message}")
        }
        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null")
            return -1
        }
        tun = pfd
        return pfd.fd
    }

    private fun teardown() {
        running = false
        generation++
        connectedSince = 0L
        VpnBridge.stopEngine()
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        lastState = "disconnected"
        stateListener?.invoke("disconnected")
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

    /** Immutable flags for the PendingIntents — mutable is disallowed on S+. */
    private val piFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    /** Tapping the notification body reopens the app. */
    private fun contentPendingIntent(): PendingIntent? {
        val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return null
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return PendingIntent.getActivity(this, 0, launch, piFlags)
    }

    /** The "Disconnect" action button routes back into onStartCommand. */
    private fun disconnectPendingIntent(): PendingIntent {
        val i = Intent(this, YellowVpnService::class.java).apply { action = ACTION_DISCONNECT }
        return PendingIntent.getService(this, 1, i, piFlags)
    }

    private fun buildNotification(text: String, connected: Boolean): Notification {
        ensureChannel()
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(if (host.isNotEmpty()) "Yellow VPN · $host" else "Yellow VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .setContentIntent(contentPendingIntent())
            .addAction(
                Notification.Action.Builder(
                    null as android.graphics.drawable.Icon?, "Disconnect", disconnectPendingIntent()
                ).build()
            )
        // Live "connected for HH:MM" ticker, only while established.
        if (connected && connectedSince != 0L) {
            builder.setWhen(System.currentTimeMillis() - (SystemClock.elapsedRealtime() - connectedSince))
                .setUsesChronometer(true)
                .setShowWhen(true)
        } else {
            builder.setShowWhen(false)
        }
        return builder.build()
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
        nm.notify(NOTIFICATION_ID, buildNotification(text, state == "established"))
    }
}
