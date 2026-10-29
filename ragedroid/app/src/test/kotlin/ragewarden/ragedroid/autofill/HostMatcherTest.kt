package ragewarden.ragedroid.autofill

import kotlinx.collections.immutable.persistentListOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import ragewarden.ragedroid.model.VaultItem

class HostMatcherTest {
    @Test
    fun normaliseHost_strips_scheme_path_port_and_www() {
        assertEquals("github.com", HostMatcher.normaliseHost("https://www.github.com:443/login"))
        assertEquals("github.com", HostMatcher.normaliseHost("github.com"))
        assertEquals("github.com", HostMatcher.normaliseHost("WWW.GitHub.COM/"))
    }

    @Test
    fun matchVaultItems_matches_exact_domain() {
        val items = listOf(item("github", "github.com"), item("aws", "console.aws.amazon.com"))
        val matched = HostMatcher.matchVaultItems(items, webDomain = "github.com", packageName = null)
        assertEquals(1, matched.size)
        assertEquals("github", matched[0].id)
    }

    @Test
    fun matchVaultItems_matches_subdomain() {
        val items = listOf(item("aws", "amazon.com"))
        val matched = HostMatcher.matchVaultItems(items, webDomain = "console.aws.amazon.com", packageName = null)
        assertEquals(1, matched.size)
    }

    @Test
    fun matchVaultItems_matches_package_name_token() {
        val items = listOf(item("github", "github.com"))
        val matched = HostMatcher.matchVaultItems(items, webDomain = null, packageName = "com.github.android")
        assertTrue(matched.any { it.id == "github" })
    }

    @Test
    fun package_with_a_generic_tld_token_does_not_match_every_dot_com_item() {
        val items = listOf(item("github", "github.com"), item("example", "example.com"))
        assertEquals(emptyList<VaultItem>(), HostMatcher.matchVaultItems(items, webDomain = null, packageName = "com.evil.app"))
    }

    @Test
    fun private_public_suffix_children_do_not_share_items() {
        val items = listOf(item("alice", "alice.github.io"), item("bob", "bob.github.io"), item("root", "github.io"))
        val matched = HostMatcher.matchVaultItems(items, webDomain = "alice.github.io", packageName = null)
        assertEquals(listOf("alice"), matched.map { it.id })
        assertEquals(emptyList<VaultItem>(), HostMatcher.matchVaultItems(items, webDomain = "github.io", packageName = null))
    }

    @Test
    fun login_subdomain_still_matches_registrable_parent() {
        val items = listOf(item("example", "example.com"), item("other", "example.org"))
        val matched = HostMatcher.matchVaultItems(items, webDomain = "login.example.com", packageName = null)
        assertEquals(listOf("example"), matched.map { it.id })
    }

    @Test
    fun androidapp_uri_matches_only_that_package() {
        val items = listOf(item("app", "androidapp://com.example.bank"))
        assertEquals(listOf("app"), HostMatcher.matchVaultItems(items, null, "com.example.bank").map { it.id })
        assertEquals(emptyList<VaultItem>(), HostMatcher.matchVaultItems(items, null, "com.example.bank.evil"))
    }

    @Test
    fun matchVaultItems_returns_empty_for_no_signal() {
        val items = listOf(item("github", "github.com"))
        val matched = HostMatcher.matchVaultItems(items, webDomain = null, packageName = null)
        assertEquals(emptyList<VaultItem>(), matched)
    }

    private fun item(id: String, site: String): VaultItem = VaultItem(
        id = id,
        name = id,
        username = "user@example",
        site = site,
        folder = "Work",
        rage = true,
        // Stanza descriptors, not recipient ids -- see data/RecipientDescriptors.kt.
        recipients = persistentListOf("piv-p256:S7Bvjg"),
        password = "",
        lastUsed = "now",
        history = 1,
    )
}
