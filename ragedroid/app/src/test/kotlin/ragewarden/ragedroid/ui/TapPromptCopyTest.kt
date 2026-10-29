package ragewarden.ragedroid.ui

import android.content.Context
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.components.InlineTapReveal
import ragewarden.ragedroid.ui.components.TapAction
import ragewarden.ragedroid.ui.components.TapPresentation
import ragewarden.ragedroid.ui.theme.RageTheme

/** The tap prompt and the paper-check copy say what the code does. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp")
class TapPromptCopyTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun prompt(action: TapAction?, copiesForAutofill: Boolean = false) = composeRule.setContent {
        RageTheme {
            InlineTapReveal(
                itemName = "Stripe Dashboard",
                itemSite = "dashboard.stripe.com",
                presentation = TapPresentation.softwareOnly("This phone"),
                onAuthorize = {},
                onCancel = {},
                initialAction = action,
                copiesForAutofill = copiesForAutofill,
            )
        }
    }

    @Test
    fun copy_for_autofill_on_the_detail_screen_says_it_copies_and_when_it_clears() {
        prompt(TapAction.Autofill, copiesForAutofill = true)
        composeRule.onNodeWithText("Copy the password to paste into dashboard.stripe.com?").assertExists()
        composeRule.onNodeWithText("Cleared from the clipboard after 30 seconds.").assertExists()
        composeRule.onNodeWithText("Autofill into dashboard.stripe.com?").assertDoesNotExist()
    }

    @Test
    fun real_autofill_still_names_its_destination() {
        prompt(TapAction.Autofill)
        composeRule.onNodeWithText("Autofill into dashboard.stripe.com?").assertExists()
    }

    @Test
    fun the_chooser_describes_copy_and_reveal_as_they_behave() {
        prompt(action = null)
        composeRule.onNodeWithText("Cleared from the clipboard after 30 seconds.").assertExists()
        composeRule.onNodeWithText("Shown for 8 seconds.").assertExists()
    }

    @Test
    fun the_paper_check_does_not_claim_the_rest_of_the_phrase_was_never_seen() {
        val text = context.getString(R.string.we_ll_only_verify_these_three)
        assertFalse(text, text.contains("never see"))
    }
}
