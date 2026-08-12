package ragewarden.ragedroid.ui

import android.app.Activity
import android.content.Context
import android.view.ContextThemeWrapper
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * `RageApp` bound `val context = LocalContext.current.applicationContext` and
 * then wrote `(context as? Activity)?.moveTaskToBack(true)` three times, one of
 * them the back handler that runs *while the vault is locked*. An application
 * context is never an `Activity`, so all three were no-ops -- a security-relevant
 * control that could not execute, which a revision of `docs/THREAT-MODEL.md`
 * then described as working.
 *
 * These two assertions are the whole bug: the application context genuinely does
 * not resolve, and the thing that replaced the cast genuinely does.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class FindActivityTest {

    @Test
    fun an_application_context_yields_no_activity() {
        val app: Context = ApplicationProvider.getApplicationContext()
        assertNull(app.findActivity())
        assertNull(app.applicationContext.findActivity())
    }

    @Test
    fun an_activity_resolves_to_itself() {
        val controller = Robolectric.buildActivity(Activity::class.java).setup()
        val activity = controller.get()
        assertSame(activity, activity.findActivity())
    }

    @Test
    fun a_theme_wrapper_around_an_activity_still_resolves() {
        val controller = Robolectric.buildActivity(Activity::class.java).setup()
        val activity = controller.get()
        // This is the shape a Compose LocalContext usually has, and the shape a
        // bare `as? Activity` would have missed.
        val wrapped: Context = ContextThemeWrapper(ContextThemeWrapper(activity, 0), 0)
        assertSame(activity, wrapped.findActivity())
    }

    @Test
    fun an_activitys_application_context_does_not_leak_back_to_the_activity() {
        val controller = Robolectric.buildActivity(Activity::class.java).setup()
        assertNull(controller.get().applicationContext.findActivity())
    }
}
