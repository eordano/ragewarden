package ragewarden.ragedroid.autofill

import android.content.Context
import android.service.autofill.FillResponse
import android.view.View
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.Folder
import ragewarden.ragedroid.data.ItemEdit
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.theme.RageTheme

/**
 * Saving a login another app submitted: what the save does to the vault, the
 * writes it makes, the in-memory hand-off of the password, the SaveInfo that
 * makes Android offer the save, and the confirmation that gates it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AutofillSaveTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun candidate(username: String = "me@example.com", password: String = "hunter2", domain: String? = "github.com") =
        SaveCandidate(domain, if (domain == null) "com.example.app" else null, domain ?: "Example", username, password.toCharArray())

    private fun login(id: String, username: String, site: String = "https://github.com", rage: Boolean = true, password: String = "") = VaultItem(
        id = id, name = id, username = username, site = site, folder = "All", rage = rage,
        recipients = persistentListOf(), password = password, lastUsed = "", history = 0, kind = VaultItemKind.Login,
    )

    private class RecordingBackend(items: List<VaultItem>) : VaultBackend {
        private val items: ImmutableList<VaultItem> = items.toImmutableList()
        val created = mutableListOf<Pair<VaultItem, ByteArray>>()
        val edited = mutableListOf<Pair<VaultItem, ItemEdit>>()
        var sawBytes: ByteArray? = null

        override fun snapshot(): ImmutableList<VaultItem> = items
        override fun get(id: String): VaultItem? = items.firstOrNull { it.id == id }
        override suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>, use: ragewarden.ragedroid.data.audit.AuditAction?): ByteArray = error("no decrypt")
        override suspend fun update(item: VaultItem, plaintext: ByteArray?): VaultItem = error("no update")
        override suspend fun create(item: VaultItem, plaintext: ByteArray?): VaultItem {
            sawBytes = plaintext
            created += item to plaintext!!.copyOf()
            return item
        }
        override suspend fun edit(item: VaultItem, edit: ItemEdit): VaultItem {
            sawBytes = edit.newSecret
            edited += item to edit.copy(newSecret = edit.newSecret?.copyOf())
            return item
        }
        override suspend fun delete(itemId: String) = error("no delete")
        override suspend fun listFolders(): ImmutableList<Folder> = persistentListOf()
        override suspend fun createFolder(name: String): Folder = error("no folders")
        override suspend fun updateFolder(folderId: String, name: String): Folder = error("no folders")
        override suspend fun deleteFolder(folderId: String) = error("no folders")
    }

    @Test
    fun a_new_site_becomes_a_protected_login_that_matches_it_next_time() {
        val plan = AutofillSave.plan(candidate(), listOf(login("other", "me@example.com", site = "https://gitlab.com")))
        val item = (plan as SavePlan.Create).item
        assertTrue(item.rage)
        assertEquals("me@example.com", item.username)
        assertEquals(VaultItemKind.Login, item.kind)
        assertEquals(listOf(item), HostMatcher.matchVaultItems(listOf(item), "github.com", null))
    }

    @Test
    fun an_app_login_is_saved_under_its_package() {
        val item = (AutofillSave.plan(candidate(domain = null), emptyList()) as SavePlan.Create).item
        assertEquals("androidapp://com.example.app", item.site)
        assertEquals("Example", item.name)
    }

    @Test
    fun the_login_for_this_site_and_username_gets_the_new_password() {
        val mine = login("mine", "me@example.com")
        val plan = AutofillSave.plan(candidate(), listOf(login("theirs", "you@example.com"), mine))
        assertEquals(SavePlan.Update(mine), plan)
    }

    @Test
    fun an_unprotected_login_already_holding_the_password_is_left_alone() {
        val plain = login("plain", "me@example.com", rage = false, password = "hunter2")
        assertEquals(SavePlan.Unchanged(plain), AutofillSave.plan(candidate(), listOf(plain)))
        val older = login("plain", "me@example.com", rage = false, password = "old")
        assertEquals(SavePlan.Update(older), AutofillSave.plan(candidate(), listOf(older)))
    }

    @Test
    fun create_writes_through_create_and_zeroes_its_copy() = runBlocking {
        val backend = RecordingBackend(emptyList())
        val plan = AutofillSave.plan(candidate(), backend.snapshot())
        AutofillSave.run(plan, "hunter2".toCharArray(), backend)
        assertArrayEquals("hunter2".toByteArray(), backend.created.single().second)
        assertTrue(backend.sawBytes!!.all { it == 0.toByte() })
        assertTrue(backend.edited.isEmpty())
    }

    @Test
    fun update_writes_the_new_password_through_edit() = runBlocking {
        val mine = login("mine", "me@example.com")
        val backend = RecordingBackend(listOf(mine))
        AutofillSave.run(AutofillSave.plan(candidate(), backend.snapshot()), "hunter2".toCharArray(), backend)
        val (item, edit) = backend.edited.single()
        assertEquals(mine, item)
        assertArrayEquals("hunter2".toByteArray(), edit.newSecret)
        assertTrue(backend.sawBytes!!.all { it == 0.toByte() })
        assertTrue(backend.created.isEmpty())
    }

    @Test
    fun the_password_is_handed_over_once_and_an_untaken_one_is_zeroed() {
        val first = candidate()
        val token = PendingSaves.put(first, now = 0)
        assertEquals(first, PendingSaves.take(token, now = 1))
        assertNull(PendingSaves.take(token, now = 2))

        val stale = candidate(password = "stale")
        val staleToken = PendingSaves.put(stale, now = 0)
        assertNull(PendingSaves.take(staleToken, now = 121_000))
        assertTrue(stale.password.all { it == '\u0000' })
    }

    private fun target(withPassword: Boolean = true) = FillTarget(
        webDomain = "github.com",
        packageName = null,
        username = AutofillCandidate(View(context).autofillId, FieldRole.Username, 1),
        password = if (withPassword) AutofillCandidate(View(context).autofillId, FieldRole.Password, 1) else null,
    )

    private fun saveInfoOf(r: FillResponse): Any? {
        var c: Class<*>? = r.javaClass
        while (c != null) {
            runCatching { return c.getDeclaredField("mSaveInfo").apply { isAccessible = true }.get(r) }
            c = c.superclass
        }
        return null
    }

    @Test
    fun every_fill_response_with_a_password_field_asks_android_to_offer_a_save() {
        assertNotNull(saveInfoOf(AutofillDatasets.response(context, listOf(login("a", "me")), target(), null)))
        assertNotNull(saveInfoOf(AutofillDatasets.lockedResponse(context, target())))
        assertNull(AutofillDatasets.saveInfo(target(withPassword = false)))
    }

    @Test
    fun nothing_is_written_until_save_is_pressed() {
        var saves = 0
        var dismissed = 0
        composeRule.setContent {
            RageTheme {
                AutofillSaveSheet(
                    site = "github.com",
                    username = "me@example.com",
                    plan = SavePlan.Create(login("new", "me@example.com")),
                    busy = false,
                    error = null,
                    onSave = { saves++ },
                    onDismiss = { dismissed++ },
                )
            }
        }
        composeRule.onNodeWithText("Save this login to Ragewarden?").assertExists()
        composeRule.onNodeWithText("Not now").performClick()
        assertEquals(0, saves)
        assertEquals(1, dismissed)
        composeRule.onNodeWithText("Save").performClick()
        assertEquals(1, saves)
    }

    @Test
    fun an_unchanged_password_offers_no_save() {
        val plain = login("GitHub", "me@example.com", rage = false, password = "hunter2")
        composeRule.setContent {
            RageTheme {
                AutofillSaveSheet("github.com", "me@example.com", SavePlan.Unchanged(plain), false, null, {}, {})
            }
        }
        composeRule.onNodeWithText("“GitHub” already has this password.").assertExists()
        composeRule.onNodeWithText("Save").assertDoesNotExist()
        composeRule.onNodeWithText("Close").assertExists()
    }
}
