package ragewarden.ragedroid.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.ui.components.InlineTapReveal
import ragewarden.ragedroid.ui.components.TapAction
import ragewarden.ragedroid.ui.components.TapPresentation
import ragewarden.ragedroid.ui.screens.EditItemScreen
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * Every control on the tap ceremony and the edit screen is announced as a
 * button and is at least 48 x 48 dp. Several were bare Box/Row + clickable:
 * TalkBack read them as unlabelled "double-tap to activate" and some were
 * 18 dp targets.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h3000dp")
class ButtonRolesTest {
    @get:Rule
    val composeRule = createComposeRule()

    private fun assertEveryClickableIsAButton() {
        val density = composeRule.density
        val minPx = with(density) { 48.dp.toPx() } - 0.5f
        val offenders = composeRule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.OnClick))
            .fetchSemanticsNodes()
            .filterNot { SemanticsProperties.EditableText in it.config }
            .filterNot { it.isButtonSized(minPx) }
            .map { "${it.config.getOrNull(SemanticsProperties.Text) ?: it.config.getOrNull(SemanticsProperties.ContentDescription)} " +
                "role=${it.config.getOrNull(SemanticsProperties.Role)} size=${it.size}" }
        assertTrue("controls without a button role or under 48dp:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }

    private fun SemanticsNode.isButtonSized(minPx: Float): Boolean =
        config.getOrNull(SemanticsProperties.Role) != null &&
            size.width >= minPx && size.height >= minPx

    private fun tap(initial: TapAction?, onAuthorize: suspend (TapAction) -> Unit = {}) {
        composeRule.setContent {
            RageTheme {
                InlineTapReveal(
                    itemName = "Stripe Dashboard",
                    itemSite = "dashboard.stripe.com",
                    presentation = TapPresentation.softwareOnly("This phone"),
                    onAuthorize = onAuthorize,
                    onCancel = {},
                    initialAction = initial,
                )
            }
        }
        composeRule.waitForIdle()
    }

    @Test
    fun the_action_chooser_controls_are_buttons() {
        tap(initial = null)
        assertEveryClickableIsAButton()
    }

    @Test
    fun the_tap_prompt_controls_are_buttons() {
        tap(initial = TapAction.Copy)
        assertEveryClickableIsAButton()
    }

    @Test
    fun the_failure_controls_are_buttons() {
        tap(initial = TapAction.Copy, onAuthorize = { error("no key answered") })
        composeRule.onNodeWithText("Authorize").performClick()
        composeRule.waitForIdle()
        composeRule.onAllNodes(SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button))
            .fetchSemanticsNodes()
            .let { assertTrue("the failure state offers no controls", it.isNotEmpty()) }
        assertEveryClickableIsAButton()
    }

    @Test
    fun the_edit_screen_controls_are_buttons() {
        val yubi = DescriptorFixture.yubiKey("Maya YubiKey", 0x07)
        val item = DescriptorFixture.protectedItem("Stripe Dashboard", wrappedTo = listOf(yubi))
        composeRule.setContent {
            RageTheme {
                CompositionLocalProvider(LocalLiveRecipients provides DescriptorFixture.live(yubi)) {
                    Box(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
                        EditItemScreen(item = item, onCancel = {}, onSave = {}, decryptCurrent = { null })
                    }
                }
            }
        }
        composeRule.waitForIdle()
        assertEveryClickableIsAButton()
    }
}
