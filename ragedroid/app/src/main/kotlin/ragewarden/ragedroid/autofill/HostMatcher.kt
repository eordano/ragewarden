package ragewarden.ragedroid.autofill

import com.google.common.net.InternetDomainName
import ragewarden.ragedroid.model.VaultItem

object HostMatcher {
    private const val ANDROID_APP_SCHEME = "androidapp://"

    fun matchVaultItems(
        items: List<VaultItem>,
        webDomain: String?,
        packageName: String?,
    ): List<VaultItem> {
        val pageSite = registrableDomain(normaliseHost(webDomain))
        val pkg = packageName?.trim()?.lowercase().orEmpty()
        val pkgSite = if (pkg.isEmpty()) null else registrableDomain(pkg.split('.').reversed().joinToString("."))
        return items.filter { item ->
            val raw = item.site.trim()
            if (raw.lowercase().startsWith(ANDROID_APP_SCHEME)) {
                return@filter pkg.isNotEmpty() && raw.substring(ANDROID_APP_SCHEME.length).lowercase() == pkg
            }
            val itemSite = registrableDomain(normaliseHost(raw)) ?: return@filter false
            when {
                pageSite != null -> pageSite == itemSite
                pkgSite != null -> pkgSite == itemSite
                else -> false
            }
        }
    }

    fun normaliseHost(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        val stripped = raw
            .trim()
            .lowercase()
            .substringAfter("://")
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .substringAfterLast('@')
            .substringBefore(':')
            .trimEnd('.')
        if (stripped.isEmpty()) return null
        return stripped.removePrefix("www.")
    }

    fun registrableDomain(host: String?): String? {
        if (host.isNullOrBlank()) return null
        val name = runCatching { InternetDomainName.from(host) }.getOrNull() ?: return host
        return when {
            name.isTopPrivateDomain || name.isUnderPublicSuffix -> name.topPrivateDomain().toString()
            name.isPublicSuffix -> null
            else -> host
        }
    }
}
