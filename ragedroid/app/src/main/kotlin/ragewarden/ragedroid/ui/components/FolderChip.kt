package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontWeight
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.Sans
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun FolderChip(
    name: String,
    active: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = rageColors
    Box(
        modifier = modifier
            .background(
                color = if (active) c.fgEmphasis else c.surfaceElevated,
                shape = RoundedCornerShape(999.dp),
            )
            .border(1.dp, c.border, RoundedCornerShape(999.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Text(
            text = name,
            style = RageType.button.copy(
                fontFamily = Sans,
                fontWeight = FontWeight.Medium,
                fontSize = 12.5.sp,
            ),
            color = if (active) c.background else c.fgPrimary,
        )
    }
}

@Preview(showBackground = true, name = "FolderChip")
@Composable
private fun PreviewFolderChips() {
    RageTheme {
        Row(
            modifier = Modifier
                .background(rageColors.background)
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FolderChip(name = "All", active = true, onClick = {})
            FolderChip(name = "Work", active = false, onClick = {})
            FolderChip(name = "Personal", active = false, onClick = {})
        }
    }
}
