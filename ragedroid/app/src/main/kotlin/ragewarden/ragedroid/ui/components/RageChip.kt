package ragewarden.ragedroid.ui.components

import ragewarden.ragedroid.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun RageChip(
    recipientCount: Int? = null,
    modifier: Modifier = Modifier,
) {
    val c = rageColors
    Row(
        modifier = modifier
            .background(c.tile, RoundedCornerShape(999.dp))
            .padding(start = 6.dp, top = 2.dp, end = 7.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Icon(
            imageVector = Icons.Outlined.Link,
            contentDescription = null,
            tint = c.accent,
            modifier = Modifier.size(11.dp),
        )
        Text(
            text = stringResource(R.string.rage),
            style = RageType.eyebrow.copy(
                fontSize = 10.5.sp,
                letterSpacing = 0.04.em,
            ),
            color = c.accent,
        )
        if (recipientCount != null) {
            Text(
                text = stringResource(R.string.dot_count, recipientCount),
                style = RageType.eyebrow.copy(
                    fontSize = 10.5.sp,
                    letterSpacing = 0.04.em,
                    fontWeight = FontWeight.Medium,
                ),
                color = c.accent.copy(alpha = 0.6f),
            )
        }
    }
}

@Preview(showBackground = true, name = "RageChip - light")
@Composable
private fun PreviewRageChipLight() {
    RageTheme(darkTheme = false) {
        Row(
            modifier = Modifier
                .background(rageColors.background)
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RageChip()
            RageChip(recipientCount = 3)
        }
    }
}

@Preview(showBackground = true, name = "RageChip - dark", backgroundColor = 0xFF1E1E1E)
@Composable
private fun PreviewRageChipDark() {
    RageTheme(darkTheme = true) {
        Row(
            modifier = Modifier
                .background(rageColors.background)
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RageChip(recipientCount = 4)
        }
    }
}
