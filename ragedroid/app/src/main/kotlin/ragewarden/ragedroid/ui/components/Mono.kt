package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun Mono(
    text: String,
    modifier: Modifier = Modifier,
    size: Int = 13,
    color: Color? = null,
    style: TextStyle = RageType.mono,
) {
    val c = rageColors
    Text(
        text = text,
        style = style.copy(fontSize = size.sp),
        color = color ?: c.fgPrimary,
        modifier = modifier,
    )
}

