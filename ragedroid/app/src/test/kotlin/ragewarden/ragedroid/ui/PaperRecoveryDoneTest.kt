package ragewarden.ragedroid.ui

import android.content.Context
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.screens.PaperRecoveryDone
import ragewarden.ragedroid.ui.theme.RageTheme

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp")
class PaperRecoveryDoneTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun the_done_step_offers_to_test_the_new_phrase_right_away() {
        var tested = 0
        var done = 0
        composeRule.setContent { RageTheme { PaperRecoveryDone(onTestNow = { tested++ }, onComplete = { done++ }) } }
        composeRule.onNodeWithText(context.getString(R.string.test_it_now))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button))
            .performClick()
        composeRule.onNodeWithText(context.getString(R.string.done)).performClick()
        assertEquals(1, tested)
        assertEquals(1, done)
    }
}
