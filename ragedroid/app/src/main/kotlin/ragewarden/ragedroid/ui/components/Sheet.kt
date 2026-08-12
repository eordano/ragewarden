package ragewarden.ragedroid.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.ui.theme.MotionTokens
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun Sheet(
    open: Boolean,
    onDismiss: () -> Unit,
    title: String? = null,
    content: @Composable () -> Unit,
) {
    val c = rageColors
    val noIndication = remember { MutableInteractionSource() }
    AnimatedVisibility(
        visible = open,
        enter = fadeIn(tween(MotionTokens.DurSlowMs, easing = MotionTokens.EaseOut)),
        exit = fadeOut(tween(MotionTokens.DurBaseMs, easing = MotionTokens.EaseIn)),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(c.backdrop)
                .clickable(
                    interactionSource = noIndication,
                    indication = null,
                    onClick = onDismiss,
                ),
            contentAlignment = Alignment.BottomCenter,
        ) {
            AnimatedVisibility(
                visible = open,
                enter = slideInVertically(
                    tween(MotionTokens.DurSlowMs, easing = MotionTokens.EaseOut),
                ) { it },
                exit = slideOutVertically(
                    tween(MotionTokens.DurBaseMs, easing = MotionTokens.EaseIn),
                ) { it },
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 600.dp)
                        .background(
                            c.surfaceElevated,
                            RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
                        )
                        .clickable(
                            interactionSource = noIndication,
                            indication = null,
                            onClick = {},
                        )
                        .padding(start = 18.dp, end = 18.dp, top = 14.dp, bottom = 28.dp)
                        .verticalScroll(rememberScrollState()),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Box(
                        modifier = Modifier
                            .width(36.dp)
                            .height(4.dp)
                            .background(c.border, RoundedCornerShape(2.dp)),
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    if (title != null) {
                        Text(
                            text = title,
                            style = RageType.h2,
                            color = c.fgEmphasis,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp),
                        )
                    }
                    Box(modifier = Modifier.fillMaxWidth()) { content() }
                }
            }
        }
    }
}

@Preview(showBackground = true, name = "Sheet - open")
@Composable
private fun PreviewSheet() {
    RageTheme {
        Box(modifier = Modifier.fillMaxSize().background(rageColors.background)) {
            Sheet(open = true, onDismiss = {}, title = "More actions") {
                Text(
                    text = "Sheet content goes here.",
                    style = RageType.body,
                    color = rageColors.fgPrimary,
                )
            }
        }
    }
}
