package io.github.galetaire.fingertip

import android.app.Activity
import android.content.ContentValues
import android.content.Intent
import android.graphics.Typeface
import android.net.VpnService
import android.os.Bundle
import android.provider.MediaStore
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * One screen: Start, Stop, Clear, Save CA certificate and the log. Built in
 * code to keep the app free of layouts and libraries.
 */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var log: TextView
    private lateinit var scroll: ScrollView
    private val onEvent: () -> Unit = { runOnUiThread { render() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()

        status = TextView(this).apply { textSize = 18f; setPadding(0, 0, 0, pad / 2) }
        val intro = TextView(this).apply {
            text = "Handshake sites, checked with DANE, on Wi-Fi and mobile data. " +
                "Start, then browse in Chrome. Once: Start, then Save CA certificate and install it " +
                "(Settings → Security → Encryption & credentials → Install a certificate → CA certificate)."
            setPadding(0, 0, 0, pad / 2)
        }
        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(Button(context).apply { text = "Start"; setOnClickListener { start() } })
            addView(Button(context).apply { text = "Stop"; setOnClickListener { stop() } })
            addView(Button(context).apply { text = "Clear"; setOnClickListener { EventLog.clear() } })
        }
        val saveCa = Button(this).apply { text = "Save CA certificate"; setOnClickListener { saveCa() } }
        log = TextView(this).apply { typeface = Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true) }
        scroll = ScrollView(this).apply { addView(log) }

        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(status, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(intro, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(buttons, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(saveCa, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
            addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        })
    }

    override fun onResume() {
        super.onResume()
        EventLog.listen(onEvent)
        render()
    }

    override fun onPause() {
        EventLog.unlisten(onEvent)
        super.onPause()
    }

    private fun render() {
        status.text = if (ProxyVpnService.running) "● On: proxy 127.0.0.1:${ProxyVpnService.PROXY_PORT}" else "○ Off"
        log.text = EventLog.text()
        scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    private fun start() {
        // The first time, Android asks the user to allow this app as a VPN
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, REQUEST_VPN) else startVpn()
    }

    @Deprecated("Activity result API kept simple for the prototype")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startVpn() else EventLog.add("VPN request declined")
        }
    }

    private fun startVpn() {
        startService(Intent(this, ProxyVpnService::class.java).setAction(ProxyVpnService.ACTION_START))
    }

    private fun stop() {
        startService(Intent(this, ProxyVpnService::class.java).setAction(ProxyVpnService.ACTION_STOP))
    }

    /**
     * Copies the local CA certificate to Downloads, where Android's
     * certificate installer can pick it up. Apps cannot install a CA
     * themselves since Android 11: the user does it in Settings.
     */
    private fun saveCa() {
        val ca = DaneProxy(this).caFile
        if (!ca.exists()) {
            EventLog.add("No CA certificate yet: tap Start first, it is created on the first start")
            return
        }
        try {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, CA_FILE_NAME)
                put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
            }
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: error("Downloads refused the file")
            contentResolver.openOutputStream(uri)!!.use { out -> ca.inputStream().use { it.copyTo(out) } }
            EventLog.add("Saved $CA_FILE_NAME to Downloads. Install it: Settings → Security & privacy → " +
                "More security settings → Encryption & credentials → Install a certificate → CA certificate")
        } catch (e: Exception) {
            EventLog.add("Could not save the CA certificate: ${e.message}")
        }
    }

    companion object {
        private const val REQUEST_VPN = 1
        private const val CA_FILE_NAME = "Fingertip-CA.crt"
    }
}
