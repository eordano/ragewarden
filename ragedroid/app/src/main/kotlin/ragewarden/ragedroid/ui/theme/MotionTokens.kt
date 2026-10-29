package ragewarden.ragedroid.ui.theme

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing

object MotionTokens {
    val EaseOut: Easing = CubicBezierEasing(0.2f, 0.8f, 0.2f, 1f)
    val EaseIn: Easing = CubicBezierEasing(0.4f, 0f, 1f, 1f)
    const val DurBaseMs: Int = 110
    const val DurSlowMs: Int = 220
}
