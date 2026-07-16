package app.yellowvpn.plugin

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * Thin entry point the app (MainActivity / a Tauri plugin) calls to drive the VPN.
 *
 * Consent flow: [consentIntent] returns a non-null Intent the first time — the
 * caller must launch it with `startActivityForResult(intent, REQ_CONSENT)` and,
 * on RESULT_OK, call [start]. Once the user has granted consent it returns null
 * and [start] can be called directly.
 */
object VpnController {
    const val REQ_CONSENT = 0x7601

    fun consentIntent(ctx: Context): Intent? = VpnService.prepare(ctx)

    fun start(
        ctx: Context,
        host: String,
        port: Int,
        user: String,
        pass: String,
        protocol: Int = 0,
        insecure: Boolean = false,
        certSha256: String = "",
        address: String = "10.0.0.2",
        mtu: Int = 1400,
    ) {
        val i = Intent(ctx, YellowVpnService::class.java).apply {
            action = YellowVpnService.ACTION_CONNECT
            putExtra("host", host)
            putExtra("port", port)
            putExtra("user", user)
            putExtra("pass", pass)
            putExtra("protocol", protocol)
            putExtra("insecure", insecure)
            putExtra("certSha256", certSha256)
            putExtra("address", address)
            putExtra("mtu", mtu)
        }
        ctx.startForegroundService(i)
    }

    fun stop(ctx: Context) {
        val i = Intent(ctx, YellowVpnService::class.java).apply {
            action = YellowVpnService.ACTION_DISCONNECT
        }
        ctx.startService(i)
    }

    fun currentState(): String = YellowVpnService.lastState

    /**
     * Entry called from Rust over JNI (see src-tauri/src/android_vpn.rs).
     * Returns "started" if the tunnel is starting, or "consent-requested" if the
     * system VPN consent dialog was launched (the user must grant it, then the
     * caller retries). Uses the app context; the consent Intent is launched as a
     * NEW_TASK activity because Rust has no Activity handle in A1.
     */
    @JvmStatic
    fun startFromNative(
        ctx: Context,
        host: String,
        port: Int,
        user: String,
        pass: String,
        protocol: Int,
        insecure: Boolean,
        certSha256: String,
        address: String,
        mtu: Int,
    ): String {
        val consent = consentIntent(ctx)
        if (consent != null) {
            consent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(consent)
            return "consent-requested"
        }
        start(ctx, host, port, user, pass, protocol, insecure, certSha256, address, mtu)
        return "started"
    }

    @JvmStatic
    fun stopFromNative(ctx: Context) = stop(ctx)

    @JvmStatic
    fun stateFromNative(): String = currentState()

    /** Convenience for an Activity: request consent if needed, else start now.
     *  Returns true if it started, false if a consent Intent was launched. */
    fun connectOrRequestConsent(
        activity: Activity,
        host: String,
        port: Int,
        user: String,
        pass: String,
        address: String = "10.0.0.2",
        mtu: Int = 1400,
    ): Boolean {
        val consent = consentIntent(activity)
        return if (consent != null) {
            activity.startActivityForResult(consent, REQ_CONSENT)
            false
        } else {
            start(activity, host, port, user, pass, address = address, mtu = mtu)
            true
        }
    }
}
