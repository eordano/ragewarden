package ragewarden.ragedroid.ui

import android.content.Context
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.screens.IntroStep
import ragewarden.ragedroid.ui.screens.RotationBanner
import ragewarden.ragedroid.ui.theme.RageTheme

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], qualifiers = "+w411dp-h891dp")
class RotationFlowTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun the_banners_x_dismisses_without_navigating_and_its_body_navigates() {
        var rotated = 0
        var dismissed = 0
        composeRule.setContent { RageTheme { RotationBanner(onRotate = { rotated++ }, onDismiss = { dismissed++ }) } }
        composeRule.onNodeWithContentDescription(context.getString(R.string.dismiss)).performClick()
        assertEquals(1, dismissed)
        assertEquals(0, rotated)
        composeRule.onNodeWithText(context.getString(R.string.recipients_changed_re_encrypt_items)).performClick()
        assertEquals(1, rotated)
    }

    @Test
    fun mark_all_rotated_is_offered_whenever_items_are_stale_even_with_unprotected_ones() {
        var marked = 0
        var began = 0
        composeRule.setContent { RageTheme { IntroStep(count = 3, staleRageCount = 2, onBegin = { began++ }, onMarkRotated = { marked++ }) } }
        composeRule.onNodeWithText(context.getString(R.string.begin)).assertHeightIsAtLeast(48.dp).performClick()
        composeRule.onNodeWithText(context.getString(R.string.mark_all_rotated)).assertHeightIsAtLeast(48.dp).performClick()
        assertEquals(1, began)
        assertEquals(1, marked)
    }

    @Test
    fun only_stale_items_offers_mark_all_rotated_and_no_begin() {
        composeRule.setContent { RageTheme { IntroStep(count = 0, staleRageCount = 2, onBegin = {}, onMarkRotated = {}) } }
        composeRule.onNodeWithText(context.getString(R.string.mark_all_rotated)).assertExists()
        composeRule.onNodeWithText(context.getString(R.string.begin)).assertDoesNotExist()
    }
}
