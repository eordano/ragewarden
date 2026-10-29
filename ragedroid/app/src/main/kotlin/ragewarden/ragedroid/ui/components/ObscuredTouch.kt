package ragewarden.ragedroid.ui.components

import android.util.Log
import android.view.MotionEvent
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInteropFilter

/** True, and logged once per gesture, when another app's window covers the target window or the touch point. */
internal fun isObscured(event: MotionEvent): Boolean {
    val obscured = event.flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
    if (obscured && event.actionMasked == MotionEvent.ACTION_DOWN) logObscured("control", event)
    return obscured
}

internal fun logObscured(where: String, event: MotionEvent) {
    if (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0) {
        Log.w("ObscuredTouch", "$where: touch ignored, window obscured at the touch point")
    } else {
        Log.w("ObscuredTouch", "$where: touch ignored, window partially obscured")
    }
}

@OptIn(ExperimentalComposeUiApi::class)
fun Modifier.rejectObscuredTouches(): Modifier = pointerInteropFilter { event -> isObscured(event) }
