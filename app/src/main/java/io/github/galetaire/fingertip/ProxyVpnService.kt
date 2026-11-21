package io.github.galetaire.fingertip

import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * The "VPN" of the prototype. It does not tunnel anything: Android lets a VPN
 * set an HTTP proxy for all apps (VpnService.Builder.setHttpProxy, Android 10+),
 * and that proxy applies on Wi-Fi and on mobile data alike. That is the only
 * reason a VPN is used: a Wi-Fi proxy setting does not work on mobile data.
 *
 * The VPN gets one private address and a route to an unused private range, so
 * no app traffic is sent into it. This app itself is excluded, so the proxy's
 * own connections go straight out.
 */
class ProxyVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private val proxy = LocalProxy(PROXY_PORT)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutDown()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startUp()
        }
        return START_STICKY
    }

    private fun startUp() {
        if (tunnel != null) return
        try {
            proxy.start()
            tunnel = Builder()
                .setSession("Fingertip")
                .addAddress("10.111.0.1", 32)
                .addRoute("10.111.0.0", 24)
                .addDisallowedApplication(packageName)
                .setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
                .establish()
            if (tunnel == null) {
                EventLog.add("VPN not allowed: tap Start again and accept the VPN request")
                proxy.stop()
            } else {
                running = true
                EventLog.add("VPN on: system proxy set to 127.0.0.1:$PROXY_PORT")
            }
        } catch (e: Exception) {
            EventLog.add("Could not start: ${e.message}")
            shutDown()
        }
    }

    private fun shutDown() {
        tunnel?.close()
        tunnel = null
        proxy.stop()
        if (running) EventLog.add("VPN off")
        running = false
    }

    // Another VPN app took over, or the user switched it off in Settings
    override fun onRevoke() {
        shutDown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutDown()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "io.github.galetaire.fingertip.START"
        const val ACTION_STOP = "io.github.galetaire.fingertip.STOP"
        const val PROXY_PORT = 8080

        @Volatile var running = false
    }
}
