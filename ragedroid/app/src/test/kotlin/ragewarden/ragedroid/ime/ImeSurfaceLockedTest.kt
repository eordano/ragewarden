package ragewarden.ragedroid.ime

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import kotlinx.collections.immutable.persistentListOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.theme.RageTheme

/**
 * The UI half of the same rule. [ImeSurface] is handed a *populated* item list
 * with `locked = true` -- a state the service never actually produces, since
 * `ImeDelivery.offer()` empties the list first -- precisely so the assertion is
 * about this composable's own behaviour and not about its caller's.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp-night")
class ImeSurfaceLockedTest {

    @get:Rule
    val composeRule = createComposeRule()

    private val items = persistentListOf(
        VaultItem(
            id = "plain",
            name = "Bank of Example",
            username = "user@example.com",
            site = "example.com",
            folder = "All",
            rage = false,
            recipients = persistentListOf(),
            password = "",
            lastUsed = "now",
            history = 0,
        ),
    )

    @Test
    fun a_locked_keyboard_lists_nothing_and_offers_no_delivery() {
        val delivered = mutableListOf<String>()
        composeRule.setContent {
            RageTheme {
                ImeSurface(
                    locked = true,
                    items = items,
                    protectedCount = 3,
                    onDeliver = { delivered += it },
                    onCancel = {},
                )
            }
        }

        composeRule.onNodeWithText("VAULT LOCKED").assertIsDisplayed()
        composeRule.onNodeWithText("Bank of Example").assertDoesNotExist()
        composeRule.onNodeWithText("UNPROTECTED CREDENTIALS ONLY").assertDoesNotExist()
        assertEquals(emptyList<String>(), delivered)
    }

    @Test
    fun an_unlocked_keyboard_lists_the_items() {
        composeRule.setContent {
            RageTheme {
                ImeSurface(
                    locked = false,
                    items = items,
                    protectedCount = 0,
                    onDeliver = {},
                    onCancel = {},
                )
            }
        }

        composeRule.onNodeWithText("UNPROTECTED CREDENTIALS ONLY").assertIsDisplayed()
        composeRule.onNodeWithText("Bank of Example").assertIsDisplayed()
        composeRule.onNodeWithText("VAULT LOCKED").assertDoesNotExist()
    }
}
