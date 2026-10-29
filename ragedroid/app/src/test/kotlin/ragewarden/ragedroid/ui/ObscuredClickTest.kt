package ragewarden.ragedroid.ui

import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.View
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageTheme

/**
 * Tapjacking: a press that arrives through another app's overlay (fully or
 * partly covering this window) must not revoke a key or release a secret.
 * The events carry the window flags Android sets for such touches.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ObscuredClickTest {
    @get:Rule
    val composeRule = createComposeRule()

    private lateinit var view: View

    private fun tap(at: Offset, flags: Int) {
        val t = SystemClock.uptimeMillis()
        fun ev(action: Int) = MotionEvent.obtain(
            t, t, action, 1,
            arrayOf(MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER }),
            arrayOf(MotionEvent.PointerCoords().apply { x = at.x; y = at.y; pressure = 1f; size = 1f }),
            0, 0, 1f, 1f, 0, 0, InputDevice.SOURCE_TOUCHSCREEN, flags,
        )
        composeRule.runOnIdle {
            view.dispatchTouchEvent(ev(MotionEvent.ACTION_DOWN))
            view.dispatchTouchEvent(ev(MotionEvent.ACTION_UP))
        }
        composeRule.waitForIdle()
    }

    private fun render(onClick: () -> Unit) {
        composeRule.setContent {
            view = LocalView.current
            RageTheme { RageButton(label = "Revoke", onClick = onClick, variant = ButtonVariant.Danger, rejectObscured = true) }
        }
        composeRule.waitForIdle()
    }

    private fun center(): Offset = composeRule.onNodeWithText("Revoke").fetchSemanticsNode().boundsInRoot.center

    @Test
    fun a_press_through_a_full_overlay_is_dropped() {
        var clicks = 0
        render { clicks++ }
        tap(center(), MotionEvent.FLAG_WINDOW_IS_OBSCURED)
        assertEquals(0, clicks)
    }

    @Test
    fun a_press_through_a_partial_overlay_is_dropped() {
        var clicks = 0
        render { clicks++ }
        tap(center(), MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)
        assertEquals(0, clicks)
    }

    @Test
    fun a_clean_press_still_lands() {
        var clicks = 0
        render { clicks++ }
        tap(center(), 0)
        assertEquals(1, clicks)
    }
}
