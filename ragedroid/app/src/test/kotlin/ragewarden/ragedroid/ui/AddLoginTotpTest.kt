package ragewarden.ragedroid.ui

import android.content.Context
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.Folder
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.screens.AddItemKind
import ragewarden.ragedroid.ui.screens.AddItemScreen
import ragewarden.ragedroid.ui.theme.RageTheme

/** A new login can carry its TOTP seed from the start: typed, or from the Scan button. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h3000dp")
class AddLoginTotpTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private class Recording : VaultBackend {
        val created = mutableListOf<VaultItem>()
        override fun snapshot(): ImmutableList<VaultItem> = persistentListOf()
        override fun get(id: String): VaultItem? = null
        override suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>, use: AuditAction?): ByteArray = error("unused")
        override suspend fun update(item: VaultItem, plaintext: ByteArray?): VaultItem = error("unused")
        override suspend fun create(item: VaultItem, plaintext: ByteArray?): VaultItem = item.also { created += it }
        override suspend fun delete(itemId: String) = Unit
        override suspend fun listFolders(): ImmutableList<Folder> = persistentListOf()
        override suspend fun createFolder(name: String): Folder = error("unused")
        override suspend fun updateFolder(folderId: String, name: String): Folder = error("unused")
        override suspend fun deleteFolder(folderId: String) = Unit
    }

    @Test
    fun a_new_login_saves_its_totp_seed() {
        val backend = Recording()
        var saved = 0
        composeRule.setContent {
            RageTheme { AddItemScreen(itemKind = AddItemKind.Login, repo = backend, onBack = {}, onSave = { _, _ -> saved++ }) }
        }
        composeRule.onNodeWithText(context.getString(R.string.scan))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button))
        composeRule.onNode(hasSetTextAction() and hasAnyAncestor(hasTestTag("add-totp"))).performTextInput("JBSWY3DPEHPK3PXP")
        composeRule.onNodeWithText(context.getString(R.string.protect_with_ragedroid)).performScrollTo().performClick()
        composeRule.onNodeWithText(context.getString(R.string.save)).performClick()
        composeRule.waitForIdle()
        assertEquals(1, saved)
        assertEquals("JBSWY3DPEHPK3PXP", backend.created.single().totpSeed)
    }
}
