package ragewarden.ragedroid.ui

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes

/**
 * String resources for UI text built outside composition: click handlers,
 * view models, label helpers, exception messages that reach the screen.
 * Composables use `stringResource`; everything else resolves here, against
 * the application context, which follows the process configuration.
 */
object UiStrings {
    @Volatile
    private var app: Context? = null

    fun install(context: Context) {
        app = context.applicationContext
    }

    fun get(@StringRes id: Int, vararg args: Any): String = context().getString(id, *args)

    fun quantity(@PluralsRes id: Int, count: Int, vararg args: Any): String =
        context().resources.getQuantityString(id, count, *args)

    private fun context(): Context = app ?: error("UiStrings.install was not called by the Application")
}

/** [UiStrings.get]. */
fun uiString(@StringRes id: Int, vararg args: Any): String = UiStrings.get(id, *args)

/** [UiStrings.quantity]. */
fun uiQuantity(@PluralsRes id: Int, count: Int, vararg args: Any): String = UiStrings.quantity(id, count, *args)
