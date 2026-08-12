package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun Field(
    label: String,
    modifier: Modifier = Modifier,
    hint: String? = null,
    content: @Composable () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(bottom = 16.dp),
    ) {
        Text(
            text = label.uppercase(),
            style = RageType.eyebrow,
            color = c.fgSecondary,
            modifier = Modifier.padding(bottom = 6.dp),
        )
        content()
        if (hint != null) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = hint,
                style = RageType.caption,
                color = c.fgSecondary,
            )
        }
    }
}

