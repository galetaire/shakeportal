package io.github.galetaire.fingertip

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.VpnService
import android.os.Bundle
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * One screen: Start, Stop, Clear and the log. Built in code to keep the
 * prototype free of layouts and libraries.
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
            text = "Prototype step 1. Start, then browse in Chrome on mobile data. " +
                "Every site Chrome opens should appear below: that proves it uses this app's proxy."
            setPadding(0, 0, 0, pad / 2)
        }
        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(Button(context).apply { text = "Start"; setOnClickListener { start() } })
            addView(Button(context).apply { text = "Stop"; setOnClickListener { stop() } })
            addView(Button(context).apply { text = "Clear"; setOnClickListener { EventLog.clear() } })
        }
        log = TextView(this).apply { typeface = Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true) }
        scroll = ScrollView(this).apply { addView(log) }

        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(status, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(intro, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(buttons, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
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

    companion object {
        private const val REQUEST_VPN = 1
    }
}
