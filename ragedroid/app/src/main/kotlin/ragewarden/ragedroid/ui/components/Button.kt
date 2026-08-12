package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.East
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

enum class ButtonVariant { Primary, Secondary, Ghost, Danger }

// Sm now only changes padding and type scale: it can no longer shrink the
// button below the 48dp touch floor enforced below. Kept because
// ItemHistoryScreen / AddItemScreen / FolderEditScreen still ask for it.
enum class ButtonSize { Sm, Md }

@Composable
fun RageButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    variant: ButtonVariant = ButtonVariant.Primary,
    size: ButtonSize = ButtonSize.Md,
    icon: ImageVector? = null,
    fullWidth: Boolean = false,
    enabled: Boolean = true,
) {
    val c = rageColors
    val (bg, fg, borderColor) = when (variant) {
        ButtonVariant.Primary -> Triple(c.accent, c.background, c.accent)
        ButtonVariant.Secondary -> Triple(c.surfaceElevated, c.fgPrimary, c.border)
        ButtonVariant.Ghost -> Triple(Color.Transparent, c.fgPrimary, Color.Transparent)
        ButtonVariant.Danger -> Triple(c.danger, c.background, c.danger)
    }
    val padding = if (size == ButtonSize.Sm) {
        PaddingValues(horizontal = 12.dp, vertical = 7.dp)
    } else {
        PaddingValues(horizontal = 18.dp, vertical = 11.dp)
    }
    val widthMod = if (fullWidth) Modifier.fillMaxWidth() else Modifier.wrapContentWidth()
    val alpha = if (enabled) 1f else 0.5f

    Row(
        modifier = modifier
            .then(widthMod)
            // Android's minimum touch target is 48x48dp and Compose hands you
            // nothing of the sort on a bare clickable() -- padding alone left
            // these buttons ~30-40dp tall. Enforced in the primitive so every
            // call site inherits it instead of each screen remembering to ask.
            .defaultMinSize(minWidth = 48.dp, minHeight = 48.dp)
            .background(bg.copy(alpha = bg.alpha * alpha), RoundedCornerShape(8.dp))
            .border(1.dp, borderColor.copy(alpha = borderColor.alpha * alpha), RoundedCornerShape(8.dp))
            .clickable(enabled = enabled, onClick = onClick)
            .padding(padding),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = fg.copy(alpha = fg.alpha * alpha),
                modifier = Modifier.size(16.dp),
            )
        }
        Text(
            text = label,
            style = if (size == ButtonSize.Sm) RageType.button else RageType.button.copy(fontSize = androidx.compose.ui.unit.TextUnit(14.5f, androidx.compose.ui.unit.TextUnitType.Sp)),
            color = fg.copy(alpha = fg.alpha * alpha),
        )
    }
}

@Preview(showBackground = true, name = "Buttons - light")
@Composable
private fun PreviewButtonsLight() {
    RageTheme(darkTheme = false) {
        androidx.compose.foundation.layout.Column(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(16.dp),
        ) {
            RageButton(label = "Primary", onClick = {})
            RageButton(label = "Secondary", onClick = {}, variant = ButtonVariant.Secondary)
            RageButton(label = "Ghost", onClick = {}, variant = ButtonVariant.Ghost)
            RageButton(label = "Danger", onClick = {}, variant = ButtonVariant.Danger)
            RageButton(label = "With icon", onClick = {}, icon = Icons.Outlined.East, fullWidth = true)
            RageButton(label = "Small", onClick = {}, size = ButtonSize.Sm, icon = Icons.Outlined.ContentCopy)
            RageButton(label = "Disabled", onClick = {}, enabled = false)
        }
    }
}

@Preview(showBackground = true, name = "Buttons - dark", backgroundColor = 0xFF1E1E1E)
@Composable
private fun PreviewButtonsDark() {
    RageTheme(darkTheme = true) {
        androidx.compose.foundation.layout.Column(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(16.dp),
        ) {
            RageButton(label = "Primary", onClick = {})
            RageButton(label = "Secondary", onClick = {}, variant = ButtonVariant.Secondary)
            RageButton(label = "Danger", onClick = {}, variant = ButtonVariant.Danger)
        }
    }
}
