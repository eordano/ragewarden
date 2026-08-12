package ragewarden.ragedroid.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper

/**
 * Unwraps a Compose `LocalContext` down to the hosting [Activity].
 *
 * This exists because `RageApp` bound `val context = LocalContext.current.applicationContext`
 * and then wrote `(context as? Activity)?.moveTaskToBack(true)` in three places,
 * including the branch that handles back *while the vault is locked*. An
 * application context is never an `Activity`, so the cast was always null and
 * all three calls were no-ops: a security-relevant control that could not
 * execute. The documentation at one point described it as working.
 *
 * A `LocalContext` inside a themed composition is typically a `ContextThemeWrapper`
 * around the Activity rather than the Activity itself, so a direct `as?` on it
 * is not reliable either -- hence the walk up the `ContextWrapper` chain. Callers
 * should prefer `androidx.activity.compose.LocalActivity` and use this as the
 * fallback.
 */
internal tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
