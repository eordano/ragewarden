package ragewarden.ragedroid.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import kotlinx.collections.immutable.ImmutableList
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.ui.screens.SearchScreen
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * `SearchScreen`'s recipient chip, against a fixture that reproduces the
 * namespace mismatch it used to get wrong.
 *
 * The chip carries a `Recipient.id` (a UUID). An item's `recipients` carries the
 * stanza descriptors the JNI layer parsed out of its own age header
 * ("piv-p256:<b64>"). `SearchScreen.kt:96` used to test one against the other,
 * so picking *any* recipient emptied the result list outright -- a filter that
 * looked live and could not match. Nothing in the repo instantiated this screen,
 * so nothing noticed.
 *
 * Every descriptor below is produced by `RecipientDescriptors.forStored`, and
 * every id by the same `toUiRecipient` mapper `RecipientStore` uses -- see
 * [DescriptorFixture]. Hand-written literals here would prove nothing.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h2400dp-night")
class SearchRecipientFilterTest {

    @get:Rule
    val composeRule = createComposeRule()

    private val yubi = DescriptorFixture.yubiKey("Maya YubiKey", 0x07)
    private val spare = DescriptorFixture.yubiKey("Spare YubiKey", 0x21)
    private val box = DescriptorFixture.strongBox("Pixel StrongBox", "ragewarden-keystore-fixture")

    /** Wrapped to the YubiKey, plus an unnameable software recipient. */
    private val stripe =
        DescriptorFixture.protectedItem("Stripe Dashboard", wrappedTo = listOf(yubi), anonymous = 1)

    /** Wrapped to both hardware keys. */
    private val hetzner = DescriptorFixture.protectedItem("Hetzner Cloud", wrappedTo = listOf(yubi, box))

    /** Wrapped to the StrongBox only. */
    private val github = DescriptorFixture.protectedItem("GitHub Org", wrappedTo = listOf(box))

    /** Not protected at all: never a hit for any recipient. */
    private val wifi = DescriptorFixture.plainItem("Family WiFi")

    private val items = DescriptorFixture.items(stripe, hetzner, github, wifi)
    private val live = DescriptorFixture.live(yubi, spare, box)

    @Before
    fun preconditions() {
        DescriptorFixture.assertNamespacesAreDisjoint(items, listOf(yubi, spare, box))
        // The chip cycles "Recipient" -> yubi -> spare -> box in
        // `LocalLiveRecipients` order (SearchScreen.kt:94). The click sequences
        // below depend on that order, so pin it rather than assume it.
        assertEquals(listOf(yubi.name, spare.name, box.name), live.map(Recipient::name))
    }

    private fun render(recipients: ImmutableList<Recipient> = live) {
        composeRule.setContent {
            RageTheme(darkTheme = true) {
                CompositionLocalProvider(LocalLiveRecipients provides recipients) {
                    Box(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
                        SearchScreen(items = items, onBack = {}, onOpen = {})
                    }
                }
            }
        }
        composeRule.waitForIdle()
    }

    /**
     * Click the recipient chip through [labels], which is the sequence of labels
     * it shows on the way to the recipient wanted -- it is a cycling chip, not a
     * menu, so there is no way to address a recipient directly.
     */
    private fun cycleTo(vararg labels: String) {
        labels.forEach { label ->
            composeRule.onNodeWithText(label).performClick()
            composeRule.waitForIdle()
        }
    }

    @Test
    fun picking_a_recipient_lists_the_items_its_stanza_actually_opens() {
        render()
        cycleTo("Recipient")

        composeRule.onNodeWithText(yubi.name).assertIsDisplayed()
        composeRule.onNodeWithText("2 results").assertIsDisplayed()
        composeRule.onNodeWithText(stripe.name).assertIsDisplayed()
        composeRule.onNodeWithText(hetzner.name).assertIsDisplayed()
        composeRule.onNodeWithText(github.name).assertDoesNotExist()
        composeRule.onNodeWithText(wifi.name).assertDoesNotExist()
    }

    /**
     * A different recipient, and not the first in the list: a filter that always
     * returned the first enrolled key's items would pass the test above and fail
     * this one.
     */
    @Test
    fun a_different_recipient_selects_a_different_set() {
        render()
        cycleTo("Recipient", yubi.name, spare.name)

        composeRule.onNodeWithText(box.name).assertIsDisplayed()
        composeRule.onNodeWithText("2 results").assertIsDisplayed()
        composeRule.onNodeWithText(hetzner.name).assertIsDisplayed()
        composeRule.onNodeWithText(github.name).assertIsDisplayed()
        composeRule.onNodeWithText(stripe.name).assertDoesNotExist()
    }

    /**
     * The control. `spare` is a genuinely enrolled hardware key that no item in
     * this vault is wrapped to, so an empty result list is the *correct* answer
     * -- and an empty list is exactly what the broken comparison produced for
     * every recipient. Without this case "the list is non-empty" would be the
     * only claim the tests above make, and a chip that ignored its selection
     * entirely would satisfy it.
     */
    @Test
    fun a_recipient_that_opens_nothing_really_does_show_nothing() {
        render()
        cycleTo("Recipient", yubi.name)

        composeRule.onNodeWithText(spare.name).assertIsDisplayed()
        composeRule.onNodeWithText("0 results").assertIsDisplayed()
        composeRule.onNodeWithText("Nothing matches that search.").assertIsDisplayed()
        composeRule.onNodeWithText(stripe.name).assertDoesNotExist()
        composeRule.onNodeWithText(github.name).assertDoesNotExist()
    }

    /**
     * A software or paper key's X25519 stanza carries nothing but the ephemeral
     * share, so it can never be matched from a header. Offering it as a chip
     * could only ever produce "0 results" for a key that may well open
     * everything, so it is not offered at all -- `SearchScreen.kt:92`.
     */
    @Test
    fun an_unnameable_recipient_is_not_offered_as_a_filter() {
        val paper = DescriptorFixture.software("Paper recovery")
        render(DescriptorFixture.live(paper))

        composeRule.onNodeWithText("Recipient").assertDoesNotExist()
        composeRule.onNodeWithText(paper.name).assertDoesNotExist()
        // The rest of the filter row is still there: a hidden chip, not a dead screen.
        composeRule.onNodeWithText("Protected only").assertIsDisplayed()
    }
}
