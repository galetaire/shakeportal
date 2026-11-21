package io.github.galetaire.fingertip

import android.content.Context

/**
 * Which names are Handshake names: anything whose top-level name is not an
 * ICANN TLD (IANA's list, downloaded at build into assets/icann-tlds.txt)
 * or a special-use name. Everything else goes straight out, as before.
 */
class IcannTlds(context: Context) {
    private val tlds: Set<String> = buildSet {
        context.assets.open(ASSET).bufferedReader().useLines { lines ->
            for (line in lines) {
                val t = line.trim().lowercase()
                if (t.isNotEmpty() && !t.startsWith("#")) add(t)
            }
        }
        addAll(SPECIAL_USE)
    }

    init {
        // A truncated list would send ICANN names to the DANE proxy
        check(tlds.size > 1000) { "only ${tlds.size} TLDs in $ASSET" }
    }

    fun isHandshake(host: String): Boolean {
        val name = host.trimEnd('.').lowercase()
        if (name.isEmpty() || name.contains(':') || IPV4.matches(name)) return false
        return name.substringAfterLast('.') !in tlds
    }

    companion object {
        const val ASSET = "icann-tlds.txt"
        // Special-use names (RFC 6761 and friends); home.arpa is under arpa
        private val SPECIAL_USE = listOf("local", "localhost", "onion", "test", "invalid", "example", "internal", "alt")
        private val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")
    }
}
