package ragewarden.ragedroid.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState

/**
 * Runs [onGone] once per [key] after the frame commits. A screen whose subject
 * vanished (a revoked recipient, a deleted item) navigates away and toasts from
 * here, never from the composition body, which re-runs on every recomposition.
 */
@Composable
internal fun LeaveWhenGone(key: Any?, onGone: () -> Unit) {
    val latest by rememberUpdatedState(onGone)
    LaunchedEffect(key) { latest() }
}
