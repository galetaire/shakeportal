package io.github.galetaire.shakeportal

/**
 * How each Handshake site was checked, for the list on the main screen.
 * The DANE proxy prints one line per change ("@site <name> <status>
 * <detail>", see go/report.go); [DaneProxy] hands those lines here.
 */
object SiteResults {
    data class Site(val name: String, val status: String, val detail: String)

    private const val MAX = 30
    private val sites = LinkedHashMap<String, Site>() // oldest first

    /** @return a readable line for the log */
    fun update(line: String): String? {
        val parts = line.removePrefix("@site ").split(" ", limit = 3)
        if (parts.size < 2) return null
        val site = Site(parts[0], parts[1], parts.getOrElse(2) { "" })
        synchronized(this) {
            sites.remove(site.name)
            sites[site.name] = site
            while (sites.size > MAX) sites.remove(sites.keys.first())
        }
        EventLog.changed()
        return "${site.name}: ${label(site.status)}" + if (site.detail.isNotEmpty()) " (${site.detail})" else ""
    }

    fun clear() {
        synchronized(this) { sites.clear() }
        EventLog.changed()
    }

    /** Newest first, at most [shown] sites */
    fun list(shown: Int = 8): List<Site> = synchronized(this) { sites.values.reversed().take(shown) }

    enum class Kind { GOOD, WARN, BAD, NEUTRAL }

    fun kind(status: String) = when (status) {
        "verified-sane", "verified" -> Kind.GOOD
        "verified-unchecked" -> Kind.WARN
        "refused", "failed" -> Kind.BAD
        else -> Kind.NEUTRAL
    }

    fun symbol(status: String) = when (kind(status)) {
        Kind.GOOD -> "✓"
        Kind.WARN -> "!"
        Kind.BAD -> "✗"
        Kind.NEUTRAL -> "–"
    }

    fun label(status: String) = when (status) {
        "verified-sane" -> "verified from its own certificate (Stateless DANE)"
        "verified" -> "verified with DNSSEC from the chain"
        "verified-unchecked" -> "verified, but the tree root is not checked yet"
        "not-dane" -> "not a DANE site: passed through as it is"
        "unsigned" -> "TLSA not signed: passed through as it is"
        "refused" -> "refused"
        "failed" -> "failed"
        else -> status
    }
}
