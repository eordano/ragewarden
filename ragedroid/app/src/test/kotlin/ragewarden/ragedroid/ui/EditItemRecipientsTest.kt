package ragewarden.ragedroid.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import kotlinx.collections.immutable.ImmutableList
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.screens.EditItemScreen
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * `EditItemScreen`'s "Recipients · view only" list.
 *
 * `EditItemScreen.kt:298` used to build this list with `it.id in item.recipients`
 * -- a `Recipient.id` (UUID) tested against stanza descriptors from the item's own
 * age header. The namespaces never intersect, so the list was permanently empty
 * and *every* protected item told its owner it had no recipients at all: the
 * screen most likely to be opened by someone about to rotate a key.
 *
 * The screen was never instantiated anywhere in the repo, unit or instrumented,
 * so the bug and its fix were both invisible to the suite.
 *
 * The viewport is deliberately tall: the recipients field lives near the bottom
 * of a `LazyColumn`, and a phone-sized viewport would leave it uncomposed --
 * absent from the semantics tree for a reason that has nothing to do with
 * descriptors, which would make every `assertDoesNotExist` below pass for free.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h3000dp-night")
class EditItemRecipientsTest {

    @get:Rule
    val composeRule = createComposeRule()

    private val yubi = DescriptorFixture.yubiKey("Maya YubiKey", 0x07)
    private val spare = DescriptorFixture.yubiKey("Spare YubiKey", 0x21)
    private val box = DescriptorFixture.strongBox("Pixel StrongBox", "ragewarden-keystore-fixture")

    private val live = DescriptorFixture.live(yubi, spare, box)

    private fun render(item: VaultItem, recipients: ImmutableList<Recipient> = live) {
        composeRule.setContent {
            RageTheme(darkTheme = true) {
                CompositionLocalProvider(LocalLiveRecipients provides recipients) {
                    Box(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
                        EditItemScreen(
                            item = item,
                            onCancel = {},
                            onSave = {},
                            decryptCurrent = { null },
                        )
                    }
                }
            }
        }
        composeRule.waitForIdle()
    }

    @Before
    fun preconditions() {
        DescriptorFixture.assertNamespacesAreDisjoint(
            listOf(DescriptorFixture.protectedItem("probe", wrappedTo = listOf(yubi, spare, box))),
            listOf(yubi, spare, box),
        )
    }

    @Test
    fun the_recipients_an_items_header_names_are_listed() {
        val item = DescriptorFixture.protectedItem("Stripe Dashboard", wrappedTo = listOf(yubi))
        render(item)

        composeRule.onNodeWithText("RECIPIENTS · VIEW ONLY").assertIsDisplayed()
        composeRule.onNodeWithText(yubi.name).assertIsDisplayed()
        // The row's own fingerprint, not just its name: this is the recipient
        // whose stanza is in the header, not merely "a recipient rendered".
        composeRule.onNodeWithText(yubi.ui.fingerprint).assertIsDisplayed()
        // Enrolled, but its stanza is not in this header.
        composeRule.onNodeWithText(spare.name).assertDoesNotExist()
        composeRule.onNodeWithText(box.name).assertDoesNotExist()
    }

    @Test
    fun an_item_wrapped_to_two_keys_lists_both_of_them() {
        val item = DescriptorFixture.protectedItem("Hetzner Cloud", wrappedTo = listOf(yubi, box))
        render(item)

        composeRule.onNodeWithText(yubi.name).assertIsDisplayed()
        composeRule.onNodeWithText(box.name).assertIsDisplayed()
        composeRule.onNodeWithText(spare.name).assertDoesNotExist()
    }

    /**
     * The control. An item wrapped only to software/paper keys genuinely has no
     * nameable recipient, so an empty list is correct here -- and an empty list
     * is what the broken comparison produced for every item. Without this case
     * the tests above would only claim "the list is non-empty", which a screen
     * that listed every enrolled recipient regardless of the header would also
     * satisfy.
     */
    @Test
    fun an_item_no_enrolled_key_is_named_in_lists_nobody() {
        val item = DescriptorFixture.protectedItem("Paper-only Cipher", anonymous = 2)
        render(item)

        composeRule.onNodeWithText("RECIPIENTS · VIEW ONLY").assertIsDisplayed()
        composeRule.onNodeWithText(yubi.name).assertDoesNotExist()
        composeRule.onNodeWithText(spare.name).assertDoesNotExist()
        composeRule.onNodeWithText(box.name).assertDoesNotExist()
        // ...and it says so, rather than implying the item has no recipients.
        composeRule.onNodeWithText(
            "Any one of these can decrypt. 2 software or paper recipient(s) are also " +
                "wrapped in -- age headers do not name those, so they cannot be listed. " +
                "Editing the recipient set lands with multi-recipient encrypt.",
        ).assertIsDisplayed()
    }

    /** An unprotected item has no age header at all: no recipients section. */
    @Test
    fun an_unprotected_item_has_no_recipients_section() {
        render(DescriptorFixture.plainItem("Family WiFi"))

        composeRule.onNodeWithText("RECIPIENTS · VIEW ONLY").assertDoesNotExist()
    }
}
