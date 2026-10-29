package ragewarden.ragedroid.ime

import android.view.inputmethod.EditorInfo
import androidx.lifecycle.Lifecycle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The keyboard's lifecycle ends at DESTROYED. On a device,
 * InputMethodService.onDestroy finishes a shown input view, so
 * onFinishInputView lands after the registry is destroyed; moving it back to
 * STARTED threw and killed the app's process (DeliveryFlowsTest on an emulator).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ImeLifecycleTest {
    @Test
    fun a_late_finish_after_destroy_leaves_it_destroyed() {
        val controller = Robolectric.buildService(RagewardenInputMethodService::class.java).create()
        val ime = controller.get()
        ime.onStartInputView(EditorInfo(), false)
        assertEquals(Lifecycle.State.RESUMED, ime.lifecycle.currentState)
        controller.destroy()
        ime.onFinishInputView(true)
        ime.onStartInputView(EditorInfo(), true)
        assertEquals(Lifecycle.State.DESTROYED, ime.lifecycle.currentState)
    }

    @Test
    fun it_shows_with_a_hardware_keyboard_attached() {
        val ime = Robolectric.buildService(RagewardenInputMethodService::class.java).create().get()
        assertTrue(ime.onEvaluateInputViewShown())
    }
}
