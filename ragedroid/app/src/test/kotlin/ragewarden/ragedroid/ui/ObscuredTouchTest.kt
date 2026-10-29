package ragewarden.ragedroid.ui

import android.view.MotionEvent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import ragewarden.ragedroid.ui.components.isObscured

@RunWith(RobolectricTestRunner::class)
class ObscuredTouchTest {
    private fun event(flags: Int): MotionEvent = MotionEvent.obtain(
        0, 0, MotionEvent.ACTION_DOWN, 1,
        arrayOf(MotionEvent.PointerProperties().apply { id = 0 }),
        arrayOf(MotionEvent.PointerCoords().apply { x = 1f; y = 1f }),
        0, 0, 1f, 1f, 0, 0, 0, flags,
    )

    @Test
    fun touches_through_any_overlay_are_rejected() {
        assertTrue(isObscured(event(MotionEvent.FLAG_WINDOW_IS_OBSCURED)))
        assertTrue(isObscured(event(MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)))
        assertFalse(isObscured(event(0)))
    }
}
