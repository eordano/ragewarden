package ragewarden.ragedroid.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.ui.theme.MotionTokens
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import androidx.compose.animation.core.tween

enum class ToastKind { Default, Success, Error }

data class Toast(val label: String, val kind: ToastKind = ToastKind.Default)

@Composable
fun ToastHost(
    toast: Toast?,
    modifier: Modifier = Modifier,
) {
    val c = rageColors
    Box(
        modifier = modifier.fillMaxWidth(),
        contentAlignment = Alignment.BottomCenter,
    ) {
        AnimatedVisibility(
            visible = toast != null,
            enter = fadeIn(tween(MotionTokens.DurSlowMs, easing = MotionTokens.EaseOut)) +
                slideInVertically(tween(MotionTokens.DurSlowMs, easing = MotionTokens.EaseOut)) { it / 2 },
            exit = fadeOut(tween(MotionTokens.DurBaseMs, easing = MotionTokens.EaseIn)) +
                slideOutVertically(tween(MotionTokens.DurBaseMs, easing = MotionTokens.EaseIn)) { it / 2 },
        ) {
            val current = toast ?: return@AnimatedVisibility
            val (bg, fg) = when (current.kind) {
                ToastKind.Error -> c.dangerStrong to Color(0xFFFAF6EE)
                ToastKind.Success -> c.success to Color(0xFFFAF6EE)
                ToastKind.Default -> c.fgEmphasis to c.background
            }
            Row(
                modifier = Modifier
                    .padding(bottom = 90.dp, start = 24.dp, end = 24.dp)
                    .widthIn(min = 220.dp, max = 360.dp)
                    .background(bg, RoundedCornerShape(8.dp))
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(text = current.label, style = RageType.sansBody, color = fg)
            }
        }
    }
}

@Preview(showBackground = true, name = "Toast - default")
@Composable
private fun PreviewToastDefault() {
    RageTheme(darkTheme = false) {
        Box(
            modifier = Modifier
                .background(rageColors.background)
                .fillMaxWidth()
                .padding(top = 200.dp),
        ) {
            ToastHost(toast = Toast("Password copied · clears in 30s"))
        }
    }
}

@Preview(showBackground = true, name = "Toast - success")
@Composable
private fun PreviewToastSuccess() {
    RageTheme(darkTheme = false) {
        Box(
            modifier = Modifier
                .background(rageColors.background)
                .fillMaxWidth()
                .padding(top = 200.dp),
        ) {
            ToastHost(toast = Toast("Saved", ToastKind.Success))
        }
    }
}
