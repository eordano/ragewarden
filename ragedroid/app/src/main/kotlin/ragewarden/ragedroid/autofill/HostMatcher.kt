package ragewarden.ragedroid.autofill

import ragewarden.ragedroid.model.VaultItem

object HostMatcher {
    fun matchVaultItems(
        items: List<VaultItem>,
        webDomain: String?,
        packageName: String?,
    ): List<VaultItem> {
        val normalisedDomain = normaliseHost(webDomain)
        val pkg = packageName?.lowercase().orEmpty()
        return items.filter { item ->
            val itemHost = normaliseHost(item.site)
            when {
                normalisedDomain != null && itemHost != null -> hostsMatch(normalisedDomain, itemHost)
                pkg.isNotEmpty() && itemHost != null -> hostsMatchPackage(pkg, itemHost)
                else -> false
            }
        }
    }

    fun normaliseHost(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        val stripped = raw
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore('/')
            .substringBefore(':')
            .trim()
            .lowercase()
        if (stripped.isEmpty()) return null
        return stripped.removePrefix("www.")
    }

    private fun hostsMatch(a: String, b: String): Boolean {
        if (a == b) return true
        if (a.endsWith(".$b") || b.endsWith(".$a")) return true
        return false
    }

    private fun hostsMatchPackage(packageName: String, host: String): Boolean {
        val pkgTokens = packageName.split('.')
        val hostTokens = host.split('.')
        if (pkgTokens.isEmpty() || hostTokens.isEmpty()) return false
        return pkgTokens.any { tok -> tok.length > 2 && hostTokens.any { it == tok } }
    }
}
