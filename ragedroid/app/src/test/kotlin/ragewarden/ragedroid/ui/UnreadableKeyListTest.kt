package ragewarden.ragedroid.ui

import android.content.Context
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import kotlinx.collections.immutable.persistentListOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.screens.VaultListScreen
import ragewarden.ragedroid.ui.theme.RageTheme

/** An unreadable key list is shown, with a reset, instead of looking like "no keys". */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp")
class UnreadableKeyListTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun the_vault_screen_says_the_key_list_is_unreadable_and_offers_a_reset() {
        var resets = 0
        composeRule.setContent {
            RageTheme {
                VaultListScreen(
                    items = persistentListOf(),
                    folders = persistentListOf("All"),
                    onOpen = {},
                    onSettings = {},
                    keyListUnreadable = true,
                    onResetKeyList = { resets++ },
                )
            }
        }
        composeRule.onNodeWithTag("key-list-unreadable").assertExists()
        composeRule.onNodeWithText(context.getString(R.string.reset_key_list)).performClick()
        assertEquals(1, resets)
    }

    @Test
    fun a_readable_list_shows_no_warning() {
        composeRule.setContent {
            RageTheme {
                VaultListScreen(items = persistentListOf(), folders = persistentListOf("All"), onOpen = {}, onSettings = {})
            }
        }
        composeRule.onNodeWithTag("key-list-unreadable").assertDoesNotExist()
    }
}
