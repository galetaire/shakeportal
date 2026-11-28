package io.github.galetaire.shakeportal

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.ProxyInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.net.Inet6Address

/**
 * The "VPN" of the app. It does not tunnel anything: Android lets a VPN set an
 * HTTP proxy for all apps (VpnService.Builder.setHttpProxy, Android 10+), and
 * that proxy applies on Wi-Fi and on mobile data alike. That is the only
 * reason a VPN is used: a Wi-Fi proxy setting does not work on mobile data.
 *
 * The VPN gets one private address and a route to an unused private range, so
 * no app traffic is sent into it. This app itself is excluded, so the
 * proxies' own connections go straight out.
 *
 * Two proxies run while it is on: [LocalProxy] (the one apps are given) and
 * [DaneProxy] (Handshake names). The DANE proxy is given the phone's DNS
 * servers and restarted when they change (Wi-Fi to mobile data and back).
 */
class ProxyVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private lateinit var dane: DaneProxy
    private lateinit var proxy: LocalProxy
    private var dnsServers: List<String> = emptyList()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        dane = DaneProxy(this)
        val tlds = IcannTlds(this)
        proxy = LocalProxy(PROXY_PORT, DaneProxy.PORT, tlds::isHandshake)
    }

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
            dnsServers = currentDnsServers()
            dane.start(dnsServers)
            proxy.start()
            tunnel = Builder()
                .setSession("ShakePortal")
                .addAddress("10.111.0.1", 32)
                .addRoute("10.111.0.0", 24)
                .addDisallowedApplication(packageName)
                .setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
                .establish()
            if (tunnel == null) {
                EventLog.add("VPN not allowed: tap Open portal again and accept the VPN request")
                shutDown()
            } else {
                running = true
                EventLog.add("VPN on: system proxy set to 127.0.0.1:$PROXY_PORT")
                watchNetwork()
            }
        } catch (e: Exception) {
            EventLog.add("Could not start: ${e.message}")
            shutDown()
        }
    }

    /**
     * The DNS servers of the network this app uses (it is outside the VPN,
     * so that is the real Wi-Fi or mobile network), as "ip:53"
     */
    private fun currentDnsServers(network: Network? = null): List<String> {
        val cm = getSystemService(ConnectivityManager::class.java)
        val props = cm.getLinkProperties(network ?: cm.activeNetwork) ?: return emptyList()
        return dnsList(props)
    }

    private fun dnsList(props: LinkProperties): List<String> = props.dnsServers.mapNotNull { addr ->
        val ip = addr.hostAddress?.substringBefore('%') ?: return@mapNotNull null
        if (addr is Inet6Address) "[$ip]:53" else "$ip:53"
    }

    private fun watchNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, props: LinkProperties) {
                val servers = dnsList(props)
                if (servers.isEmpty() || servers == dnsServers || tunnel == null) return
                dnsServers = servers
                EventLog.add("Network changed: restarting the DANE proxy")
                dane.stop()
                dane.start(servers)
            }
        }
        cm.registerDefaultNetworkCallback(callback)
        networkCallback = callback
    }

    private fun shutDown() {
        networkCallback?.let {
            try {
                getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        tunnel?.close()
        tunnel = null
        proxy.stop()
        dane.stop()
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
        const val ACTION_START = "io.github.galetaire.shakeportal.START"
        const val ACTION_STOP = "io.github.galetaire.shakeportal.STOP"
        const val PROXY_PORT = 8080

        @Volatile var running = false
    }
}
