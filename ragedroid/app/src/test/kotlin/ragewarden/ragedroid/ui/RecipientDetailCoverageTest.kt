package ragewarden.ragedroid.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.screens.RecipientDetailScreen
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * `RecipientDetailScreen`'s "CAN UNLOCK" list, its COVERAGE meter and its SOLE
 * badge -- the three surfaces that answer "what does this key actually open?"
 * before someone revokes it.
 *
 * Two separate comparisons on this screen tested a `Recipient.id` (UUID) against
 * an item's stanza descriptors (`RecipientDetailScreen.kt:84` for the list and
 * the count, `:336` for the SOLE badge). Neither namespace ever intersects the
 * other, so the list was permanently empty, coverage was permanently "0 of N",
 * and SOLE -- "revoking this makes the item unopenable" -- never once appeared.
 * The screen is not instantiated anywhere else in the repo, unit or
 * instrumented, so reverting either fix left every suite green.
 *
 * Rendering it on the JVM needs [EntryPointApplication] and
 * [installVaultBackend]; see `VaultBridgeHarness.kt` for why, and for what goes
 * wrong loudly rather than quietly if those stop working.
 *
 * Assertions are on existence in the semantics tree rather than on display:
 * ragedroid sets FLAG_SECURE, every capture of it is blank by design, and the
 * page is a tall scrolling column whose lower half is off-viewport at any
 * plausible device size.
 */
@RunWith(RobolectricTestRunner::class)
@Config(
    sdk = [33],
    qualifiers = "+w411dp-h891dp-night",
    application = EntryPointApplication::class,
)
class RecipientDetailCoverageTest {

    @get:Rule
    val composeRule = createComposeRule()

    private val yubi = DescriptorFixture.yubiKey("Maya YubiKey", 0x07)
    private val spare = DescriptorFixture.yubiKey("Spare YubiKey", 0x21)
    private val box = DescriptorFixture.strongBox("Pixel StrongBox", "ragewarden-keystore-fixture")

    @After
    fun clearBackend() {
        installVaultBackend(null)
    }

    private fun render(recipient: Recipient, vault: List<VaultItem>) {
        DescriptorFixture.assertNamespacesAreDisjoint(vault, listOf(yubi, spare, box))
        installVaultBackend(FakeVaultBackend(vault))
        composeRule.setContent {
            RageTheme(darkTheme = true) {
                Box(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
                    RecipientDetailScreen(recipient = recipient, onBack = {})
                }
            }
        }
        composeRule.waitForIdle()
    }

    /**
     * The revoke sheet quotes the coverage count in words ("The 7 items already
     * wrapped to it"), which is the one place the number appears unambiguously
     * -- the meter renders it as a bare "7" that no query can tell apart from any
     * other 7 on the page.
     */
    private fun openRevokeSheet() {
        composeRule.onNodeWithText("Revoke this recipient").performScrollTo().performClick()
        composeRule.waitForIdle()
    }

    private fun assertSheetSays(fragment: String) {
        composeRule.onNodeWithText(fragment, substring = true).assertExists()
    }

    @Test
    fun the_items_a_key_can_open_are_listed_and_counted() {
        val covered = (1..7).map {
            DescriptorFixture.protectedItem("Covered Cipher $it", wrappedTo = listOf(yubi))
        }
        val elsewhere = (1..2).map {
            DescriptorFixture.protectedItem("Foreign Cipher $it", wrappedTo = listOf(box))
        }
        val vault = covered + elsewhere + listOf(DescriptorFixture.plainItem("Family WiFi"))
        render(yubi.ui, vault)

        // Header count: rendered only when the list runs past the six rows shown.
        composeRule.onNodeWithText("7 items").assertExists()
        composeRule.onNodeWithText("+ 1 more").assertExists()
        composeRule.onNodeWithText(" of 9 protected items").assertExists()

        covered.take(6).forEach { composeRule.onNodeWithText(it.name).assertExists() }
        elsewhere.forEach { composeRule.onNodeWithText(it.name).assertDoesNotExist() }
        composeRule.onNodeWithText("Family WiFi").assertDoesNotExist()

        // Not "no item is protected for this key yet", which is what a screen
        // comparing ids against descriptors said about every key ever enrolled.
        composeRule.onNodeWithText("No item is protected for this key yet. Re-encrypt items to add it.")
            .assertDoesNotExist()

        openRevokeSheet()
        assertSheetSays("The 7 items already protected with it")
    }

    /**
     * SOLE means "rotating this item away from this recipient makes it
     * unopenable" -- one stanza in the header, and it is this key's. It is the
     * loudest warning on the screen and it had never been shown to anyone.
     */
    @Test
    fun the_sole_recipient_of_an_item_is_badged_as_such() {
        val solo = DescriptorFixture.protectedItem(
            "Solo Cipher",
            folder = "Work",
            wrappedTo = listOf(yubi),
        )
        val shared = DescriptorFixture.protectedItem(
            "Shared Cipher",
            folder = "Infra",
            wrappedTo = listOf(yubi, box),
        )
        render(yubi.ui, listOf(solo, shared))

        composeRule.onNodeWithText("Solo Cipher").assertExists()
        composeRule.onNodeWithText("Shared Cipher").assertExists()
        // Row subtitles, so the badge below is pinned to a row of known arity
        // rather than to whichever row happened to render first.
        composeRule.onNodeWithText("Work · 1 recipients").assertExists()
        composeRule.onNodeWithText("Infra · 2 recipients").assertExists()

        composeRule.onAllNodesWithText("SOLE").assertCountEquals(1)

        composeRule.onNodeWithText("This recipient can decrypt every protected item.").assertExists()
        openRevokeSheet()
        assertSheetSays("The 2 items already protected with it")
    }

    /**
     * The control, and the reason the two tests above are not merely "something
     * rendered": `spare` is a real, enrolled hardware key that this vault has
     * never been encrypted to, so an empty list and a zero count are *correct*
     * here -- and are exactly what the broken screen produced for every key.
     */
    @Test
    fun a_key_that_opens_nothing_is_shown_as_covering_nothing() {
        val vault = listOf(
            DescriptorFixture.protectedItem("Solo Cipher", wrappedTo = listOf(yubi)),
            DescriptorFixture.protectedItem("Shared Cipher", wrappedTo = listOf(yubi, box)),
            DescriptorFixture.protectedItem("Foreign Cipher", wrappedTo = listOf(box)),
        )
        render(spare.ui, vault)

        composeRule
            .onNodeWithText("No items use this key yet. It is added the next time items are re-encrypted.")
            .assertExists()
        composeRule.onNodeWithText("No item is protected for this key yet. Re-encrypt items to add it.")
            .assertExists()
        composeRule.onNodeWithText(" of 3 protected items").assertExists()
        composeRule.onAllNodesWithText("SOLE").assertCountEquals(0)
        composeRule.onNodeWithText("Solo Cipher").assertDoesNotExist()

        openRevokeSheet()
        assertSheetSays("The 0 items already protected with it")
    }

    /**
     * A software or paper key's X25519 stanza carries only the ephemeral share,
     * so no header can name it and its coverage is *unknowable*, not zero.
     * Saying "0 of 3" about a paper key that may open everything is the same
     * class of lie as the id/descriptor mismatch, so the screen refuses to say
     * it -- and the revoke copy drops the number rather than quoting a zero.
     */
    @Test
    fun an_unnameable_key_reports_unknowable_coverage_not_zero() {
        val paper = DescriptorFixture.software("Paper recovery")
        val vault = listOf(
            DescriptorFixture.protectedItem("Solo Cipher", wrappedTo = listOf(yubi)),
            DescriptorFixture.protectedItem("Shared Cipher", wrappedTo = listOf(yubi, box)),
            DescriptorFixture.protectedItem("Foreign Cipher", wrappedTo = listOf(box)),
        )
        installVaultBackend(FakeVaultBackend(vault))
        composeRule.setContent {
            RageTheme(darkTheme = true) {
                Box(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
                    RecipientDetailScreen(recipient = paper.ui, onBack = {})
                }
            }
        }
        composeRule.waitForIdle()

        composeRule.onNodeWithText(
            "Items protected with this key can't be listed: an item does not " +
                "record which key of this kind can open it.",
        ).assertExists()
        composeRule.onNodeWithText(
            "Items do not record this kind of key, so coverage can't be counted " +
                "from here. It may well open every item.",
        ).assertExists()
        composeRule.onNodeWithText("No item is protected for this key yet. Re-encrypt items to add it.")
            .assertDoesNotExist()

        openRevokeSheet()
        assertSheetSays("Items already protected with it stay readable by it until each one is re-encrypted, so")
        composeRule.onNodeWithText("The 0 items already protected with it", substring = true)
            .assertDoesNotExist()
    }
}
