package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun RecipientPip(
    kind: RecipientKind,
    modifier: Modifier = Modifier,
) {
    val c = rageColors
    val icon = when (kind) {
        RecipientKind.YubiKey -> Icons.Outlined.Nfc
        RecipientKind.Fido2 -> Icons.Outlined.Fingerprint
        RecipientKind.PasskeyPrf -> Icons.Outlined.Fingerprint
        RecipientKind.StrongBox -> Icons.Outlined.Memory
        RecipientKind.Recovery -> Icons.Outlined.Description
        RecipientKind.Software -> Icons.Outlined.Shield
    }
    Box(
        modifier = modifier
            .size(28.dp)
            .background(c.tile, RoundedCornerShape(6.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = c.accent,
            modifier = Modifier.size(15.dp),
        )
    }
}

@Preview(showBackground = true, name = "RecipientPips")
@Composable
private fun PreviewRecipientPips() {
    RageTheme {
        Row(
            modifier = Modifier
                .background(rageColors.background)
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RecipientKind.entries.forEach { kind -> RecipientPip(kind = kind) }
        }
    }
}
