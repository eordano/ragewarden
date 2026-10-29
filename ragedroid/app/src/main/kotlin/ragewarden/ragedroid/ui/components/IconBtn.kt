package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun IconBtn(
    icon: ImageVector,
    contentDescription: String?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    tint: Color? = null,
    iconSize: Int = 20,
) {
    val c = rageColors
    IconButton(
        onClick = onClick,
        modifier = modifier.size(48.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = contentDescription,
            tint = tint ?: c.fgPrimary,
            modifier = Modifier.size(iconSize.dp),
        )
    }
}

@Preview(showBackground = true, name = "IconBtns")
@Composable
private fun PreviewIconBtns() {
    RageTheme {
        Row(
            modifier = Modifier
                .size(width = 200.dp, height = 60.dp),
        ) {
            IconBtn(icon = Icons.Outlined.Settings, contentDescription = "Settings", onClick = {})
            IconBtn(icon = Icons.Outlined.MoreVert, contentDescription = "More", onClick = {})
            IconBtn(
                icon = Icons.Outlined.MoreVert,
                contentDescription = "Danger",
                onClick = {},
                tint = rageColors.dangerStrong,
            )
        }
    }
}
