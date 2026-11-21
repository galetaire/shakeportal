package io.github.galetaire.shakeportal

import android.app.Activity
import android.content.ContentValues
import android.content.Intent
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.net.VpnService
import android.os.Bundle
import android.provider.MediaStore
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * One screen of cards: on/off with one big button, the CA certificate
 * (installed or not, its fingerprint), how each Handshake site was checked,
 * and the log (folded away by default). Built in code to keep the app free
 * of layouts and libraries; follows the phone's light or dark mode.
 */
class MainActivity : Activity() {
    private lateinit var c: Palette
    private var density = 1f

    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusText: TextView
    private lateinit var toggle: TextView
    private lateinit var caChip: TextView
    private lateinit var caSteps: TextView
    private lateinit var caSave: TextView
    private lateinit var caFingerprint: TextView
    private lateinit var siteRows: LinearLayout
    private lateinit var logToggle: TextView
    private lateinit var log: TextView
    private var logShown = false
    private var caChecked = false
    private var checkedFingerprint: String? = null
    private var caInstalledNow: Boolean? = null
    private val onEvent: () -> Unit = { runOnUiThread { render() } }

    /** The screen's colours, for light or dark mode */
    private class Palette(dark: Boolean) {
        val bg = if (dark) 0xFF0F1318.toInt() else 0xFFF2F4F7.toInt()
        val card = if (dark) 0xFF181E26.toInt() else 0xFFFFFFFF.toInt()
        val stroke = if (dark) 0xFF252D37.toInt() else 0xFFE2E7ED.toInt()
        val text = if (dark) 0xFFE9EDF2.toInt() else 0xFF131A22.toInt()
        val muted = if (dark) 0xFF8D99A6.toInt() else 0xFF5F6C79.toInt()
        val accent = if (dark) 0xFF2FC98E.toInt() else 0xFF0E9F6A.toInt()
        val onAccent = if (dark) 0xFF04271A.toInt() else 0xFFFFFFFF.toInt()
        val warn = if (dark) 0xFFE9B949.toInt() else 0xFFB7791F.toInt()
        val bad = if (dark) 0xFFF26B76.toInt() else 0xFFD3414E.toInt()
        val ripple = if (dark) 0x33FFFFFF else 0x22000000
        val code = if (dark) 0xFF11161C.toInt() else 0xFFF5F7FA.toInt()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dark = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        c = Palette(dark)
        density = resources.displayMetrics.density
        window.setBackgroundDrawable(ColorDrawable(c.bg))

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(header())
            addView(statusCard())
            addView(certificateCard())
            addView(sitesCard())
            addView(logCard())
        }
        val root = ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(c.bg)
            addView(content)
        }
        // Since Android 15 apps draw under the status and navigation bars: keep clear of them.
        // The status bar stays clear while scrolling; the gesture bar may sit over scrolled cards.
        root.setOnApplyWindowInsetsListener { _, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            root.setPadding(bars.left, bars.top, bars.right, 0)
            content.setPadding(dp(16), dp(12), dp(16), bars.bottom + dp(16))
            insets
        }
        setContentView(root)
        // Dark status bar icons on the light background (needs the window's views, so after setContentView)
        val lightBars = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
        window.insetsController?.setSystemBarsAppearance(if (dark) 0 else lightBars, lightBars)
    }

    override fun onResume() {
        super.onResume()
        EventLog.listen(onEvent)
        caChecked = false // the user may have just installed it in Settings
        render()
    }

    override fun onPause() {
        EventLog.unlisten(onEvent)
        super.onPause()
    }

    // ---- Building the screen ----

    private fun header() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(4), dp(8), dp(4), dp(16))
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(android.widget.ImageView(context).apply { setImageResource(R.mipmap.ic_launcher) },
                LinearLayout.LayoutParams(dp(44), dp(44)).apply { marginEnd = dp(12) })
            addView(text("ShakePortal", 30f, c.text, bold = true))
        })
        addView(text("Handshake sites, checked with DANE, on Wi-Fi and mobile data", 14f, c.muted).apply {
            setPadding(0, dp(2), 0, 0)
        })
    }

    private fun statusCard() = card().apply {
        statusDot = View(context)
        statusTitle = text("", 22f, c.text, bold = true)
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(statusDot, LinearLayout.LayoutParams(dp(12), dp(12)).apply { marginEnd = dp(10) })
            addView(statusTitle)
        })
        statusText = text("", 14f, c.muted).apply { setPadding(0, dp(6), 0, dp(16)) }
        addView(statusText)
        toggle = button("", filled = true) { if (ProxyVpnService.running) stop() else start() }
        addView(toggle, LinearLayout.LayoutParams(MATCH_PARENT, dp(52)))
    }

    private fun certificateCard() = card().apply {
        caChip = chip()
        addView(titleRow("Certificate", caChip))
        caSteps = text(
            "Install it once, so Chrome trusts the sites this app checks:\n" +
                "1. Tap Save CA certificate.\n" +
                "2. Settings → Security & privacy → More security settings → Encryption & credentials → " +
                "Install a certificate → CA certificate → ShakePortal-CA.crt (in Downloads).",
            14f, c.muted,
        ).apply { setLineSpacing(0f, 1.15f); setPadding(0, dp(10), 0, dp(12)) }
        addView(caSteps)
        caSave = button("Save CA certificate", filled = false) { saveCa() }
        addView(caSave, LinearLayout.LayoutParams(MATCH_PARENT, dp(46)))
        addView(text("SHA-256 fingerprint", 12f, c.muted, bold = true).apply { setPadding(0, dp(14), 0, dp(4)) })
        caFingerprint = text("", 11f, c.text).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setLineSpacing(0f, 1.2f)
            background = rounded(c.code, dp(8).toFloat(), stroke = c.stroke)
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }
        addView(caFingerprint)
        addView(text("Compare it in Settings → Encryption & credentials → Trusted credentials → User.", 12f, c.muted).apply {
            setPadding(0, dp(6), 0, 0)
        })
    }

    private fun sitesCard() = card().apply {
        addView(titleRow("Handshake sites", null))
        siteRows = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(4), 0, 0) }
        addView(siteRows)
    }

    private fun logCard() = card().apply {
        logToggle = smallButton("Show") { logShown = !logShown; render() }
        val clear = smallButton("Clear") { SiteResults.clear(); EventLog.clear() }
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(text("Log", 17f, c.text, bold = true), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            addView(clear)
            addView(logToggle)
        })
        log = text("", 11f, c.muted).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(0, dp(10), 0, 0)
        }
        addView(log)
    }

    // ---- Showing the state ----

    private fun render() {
        val on = ProxyVpnService.running
        statusDot.background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(if (on) c.accent else c.muted) }
        statusTitle.text = if (on) "On" else "Off"
        statusText.text = if (on) "Handshake names go through the checking proxy (127.0.0.1:${ProxyVpnService.PROXY_PORT}). Other sites are untouched."
        else "Tap Start, then open a Handshake site in Chrome, such as https://belikebill/"
        styleButton(toggle, filled = !on)
        toggle.text = if (on) "Stop" else "Start"

        val proxy = DaneProxy(this)
        val fingerprint = proxy.caFingerprint()
        // Reading Android's CA store is slow-ish: once per return to the app, or when the CA appears
        if (!caChecked || fingerprint != checkedFingerprint) {
            caInstalledNow = proxy.caInstalled()
            checkedFingerprint = fingerprint
            caChecked = true
        }
        val installed = caInstalledNow
        when {
            fingerprint == null -> chipStyle(caChip, "Not created yet", c.muted)
            installed == true -> chipStyle(caChip, "✓ Installed", c.accent)
            installed == false -> chipStyle(caChip, "Not installed", c.warn)
            else -> chipStyle(caChip, "Created", c.muted)
        }
        val needsInstall = installed != true
        caSteps.visibility = if (needsInstall) View.VISIBLE else View.GONE
        caSave.visibility = if (needsInstall && fingerprint != null) View.VISIBLE else View.GONE
        caFingerprint.text = fingerprint?.chunked(48)?.joinToString("\n") ?: "Created on the first Start."

        siteRows.removeAllViews()
        val sites = SiteResults.list()
        if (sites.isEmpty()) {
            siteRows.addView(text("No Handshake sites yet. Each site you open shows here with how it was checked.", 14f, c.muted).apply {
                setPadding(0, dp(8), 0, dp(4))
            })
        }
        sites.forEachIndexed { i, s -> siteRows.addView(siteRow(s, divider = i > 0)) }

        logToggle.text = if (logShown) "Hide" else "Show"
        log.visibility = if (logShown) View.VISIBLE else View.GONE
        if (logShown) log.text = EventLog.text().lines().takeLast(120).joinToString("\n")
    }

    private fun siteRow(s: SiteResults.Site, divider: Boolean) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        if (divider) background = topLine() // before the padding: a background resets it
        setPadding(0, dp(12), 0, dp(12))
        val tone = when (SiteResults.kind(s.status)) {
            SiteResults.Kind.GOOD -> c.accent
            SiteResults.Kind.WARN -> c.warn
            SiteResults.Kind.BAD -> c.bad
            SiteResults.Kind.NEUTRAL -> c.muted
        }
        addView(text(SiteResults.symbol(s.status), 14f, tone, bold = true).apply {
            gravity = Gravity.CENTER
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(tone and 0x00FFFFFF or 0x26000000) }
        }, LinearLayout.LayoutParams(dp(30), dp(30)).apply { marginEnd = dp(12); topMargin = dp(2) })
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            addView(text(s.name, 16f, c.text, bold = true).apply { maxLines = 1; ellipsize = TextUtils.TruncateAt.END })
            addView(text(SiteResults.label(s.status), 13f, c.muted))
            if (SiteResults.kind(s.status) == SiteResults.Kind.BAD && s.detail.isNotEmpty()) {
                addView(text(s.detail.take(160), 12f, c.bad).apply { setPadding(0, dp(2), 0, 0) })
            }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    }

    // ---- Small building blocks ----

    private fun dp(v: Int) = (v * density).toInt()

    private fun text(s: String, size: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
        text = s
        textSize = size
        setTextColor(color)
        if (bold) typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
    }

    private fun rounded(fill: Int, radius: Float, stroke: Int? = null) = GradientDrawable().apply {
        setColor(fill)
        cornerRadius = radius
        if (stroke != null) setStroke(dp(1), stroke)
    }

    private fun topLine() = GradientDrawable().apply {
        // A 1 dp line along the top edge: a stroke drawn by a shape shifted up and sideways
        setColor(Color.TRANSPARENT)
        setStroke(dp(1), c.stroke)
    }.let { android.graphics.drawable.InsetDrawable(it, -dp(2), 0, -dp(2), -dp(2)) }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(c.card, dp(20).toFloat(), stroke = c.stroke)
        setPadding(dp(18), dp(18), dp(18), dp(18))
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(12) }
    }

    private fun titleRow(title: String, right: View?) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(text(title, 17f, c.text, bold = true), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        if (right != null) addView(right)
    }

    private fun chip() = TextView(this).apply {
        textSize = 12f
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        setPadding(dp(10), dp(4), dp(10), dp(4))
    }

    private fun chipStyle(chip: TextView, label: String, tone: Int) {
        chip.text = label
        chip.setTextColor(tone)
        chip.background = rounded(tone and 0x00FFFFFF or 0x22000000, dp(12).toFloat())
    }

    private fun button(label: String, filled: Boolean, onClick: () -> Unit) = TextView(this).apply {
        text = label
        textSize = 16f
        gravity = Gravity.CENTER
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
        styleButton(this, filled)
    }

    private fun styleButton(b: TextView, filled: Boolean) {
        val radius = dp(14).toFloat()
        val shape = if (filled) rounded(c.accent, radius) else rounded(Color.TRANSPARENT, radius, stroke = c.stroke)
        b.background = RippleDrawable(ColorStateList.valueOf(c.ripple), shape, rounded(Color.BLACK, radius))
        b.setTextColor(if (filled) c.onAccent else c.text)
    }

    private fun smallButton(label: String, onClick: () -> Unit) = TextView(this).apply {
        text = label
        textSize = 14f
        setTextColor(c.accent)
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        setPadding(dp(12), dp(6), dp(12), dp(6))
        background = RippleDrawable(ColorStateList.valueOf(c.ripple), null, rounded(Color.BLACK, dp(10).toFloat()))
        isClickable = true
        setOnClickListener { onClick() }
    }

    // ---- Actions ----

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
            android.widget.Toast.makeText(this, "Saved $CA_FILE_NAME to Downloads", android.widget.Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            EventLog.add("Could not save the CA certificate: ${e.message}")
        }
    }

    companion object {
        private const val REQUEST_VPN = 1
        private const val CA_FILE_NAME = "ShakePortal-CA.crt"
    }
}
