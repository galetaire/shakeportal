package io.github.galetaire.fingertip

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The lines the main screen shows: what the proxy saw and what the VPN did.
 * Kept in memory only, newest last, at most [MAX] lines.
 */
object EventLog {
    private const val MAX = 300
    private val lines = ArrayDeque<String>()
    private val listeners = mutableListOf<() -> Unit>()
    private val time = SimpleDateFormat("HH:mm:ss", Locale.ROOT)

    fun add(message: String) {
        synchronized(this) {
            lines.addLast("${time.format(Date())}  $message")
            while (lines.size > MAX) lines.removeFirst()
        }
        val toCall = synchronized(listeners) { listeners.toList() }
        toCall.forEach { it() }
    }

    fun text(): String = synchronized(this) { lines.joinToString("\n") }

    fun clear() {
        synchronized(this) { lines.clear() }
        add("Log cleared")
    }

    fun listen(listener: () -> Unit) = synchronized(listeners) { listeners.add(listener) }

    fun unlisten(listener: () -> Unit) = synchronized(listeners) { listeners.remove(listener) }
}
