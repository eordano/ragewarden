package ragewarden.ragedroid.ui

import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class LeaveWhenGoneTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun a_vanished_subject_toasts_and_navigates_once_however_often_the_screen_recomposes() {
        var left = 0
        var tick by mutableIntStateOf(0)
        composeRule.setContent {
            Text("tick $tick")
            LeaveWhenGone("recipient-1") { left++ }
        }
        composeRule.waitForIdle()
        repeat(5) {
            tick++
            composeRule.waitForIdle()
        }
        assertEquals(1, left)
    }
}
