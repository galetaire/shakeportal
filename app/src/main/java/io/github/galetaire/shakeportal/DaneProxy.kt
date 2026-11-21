package io.github.galetaire.shakeportal

import android.content.Context
import java.io.File
import kotlin.concurrent.thread

/**
 * Runs shakeportald, the DANE proxy for Handshake names (Go, in go/), as a
 * child process. It ships in the APK as libshakeportald.so, so Android installs
 * it with the native libraries: the one place an app may run its own
 * programs from.
 *
 * It listens on 127.0.0.1:[PORT]. LocalProxy forwards Handshake names to it;
 * everything else never reaches it. Its log lines go to the app's log.
 */
class DaneProxy(private val context: Context) {
    @Volatile private var process: Process? = null

    val running: Boolean get() = process?.isAlive == true

    /** The CA certificate to install on the phone; created on the first start */
    val caFile: File get() = File(context.filesDir, "dane/ca/ca.crt")

    /**
     * The CA certificate's SHA-256 fingerprint, as Android shows it under
     * Settings → Trusted credentials → User, or null before the first start
     */
    fun caFingerprint(): String? = try {
        val cert = caFile.inputStream().use {
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(it)
        }
        java.security.MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString(":") { "%02X".format(it) }
    } catch (_: Exception) {
        null
    }

    /**
     * Whether the CA certificate is among the user-installed CAs, or null
     * when that cannot be told (no certificate yet, or the store refused)
     */
    fun caInstalled(): Boolean? = try {
        val cert = caFile.inputStream().use {
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(it)
        }
        val store = java.security.KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        store.aliases().toList().any { it.startsWith("user:") && store.getCertificate(it) == cert }
    } catch (_: Exception) {
        null
    }

    /** @param dnsServers the phone's DNS servers, for the proxy's own ICANN lookups */
    @Synchronized
    fun start(dnsServers: List<String>) {
        if (running) return
        val program = File(context.applicationInfo.nativeLibraryDir, "libshakeportald.so")
        val data = File(context.filesDir, "dane").apply { mkdirs() }
        val tlds = File(context.filesDir, "icann-tlds.txt")
        context.assets.open(IcannTlds.ASSET).use { input -> tlds.outputStream().use { input.copyTo(it) } }

        val builder = ProcessBuilder(
            program.path,
            "-listen", "127.0.0.1:$PORT",
            "-data", data.path,
            "-tlds", tlds.path,
            "-dns", dnsServers.joinToString(","),
        ).redirectErrorStream(true)
        // Where Android keeps the trusted CAs (for the proof services' HTTPS)
        builder.environment()["SSL_CERT_DIR"] = "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts"
        val started = builder.start()
        process = started
        EventLog.add("DANE proxy starting (DNS ${dnsServers.joinToString(", ").ifEmpty { "none" }})")
        thread(name = "dane-log", isDaemon = true) {
            try {
                started.inputStream.bufferedReader().forEachLine { line ->
                    if (line.startsWith("@site ")) {
                        SiteResults.update(line)?.let { EventLog.add("site   $it".take(240)) }
                    } else {
                        EventLog.add("dane   $line".take(240))
                    }
                }
            } catch (_: Exception) {
            }
            val code = started.waitFor()
            if (process === started) EventLog.add("DANE proxy stopped unexpectedly (exit $code)")
        }
    }

    @Synchronized
    fun stop() {
        val p = process ?: return
        process = null
        // Closing stdin tells it to exit; destroy in case it does not
        try {
            p.outputStream.close()
        } catch (_: Exception) {
        }
        p.destroy()
    }

    companion object {
        const val PORT = 8081
    }
}
