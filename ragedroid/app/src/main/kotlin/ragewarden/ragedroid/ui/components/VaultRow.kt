package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.persistentListOf
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun VaultRow(
    item: VaultItem,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val c = rageColors
    val initials = item.name.filter { it.isLetter() }.take(2).uppercase().ifEmpty { "XX" }

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(
                        color = if (item.rage) c.tile else c.surfaceElevated,
                        shape = RoundedCornerShape(8.dp),
                    )
                    .border(1.dp, c.border, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                val avatarTint = if (item.rage) c.accent else c.fgSecondary
                when (item.kind) {
                    VaultItemKind.Card -> Icon(
                        imageVector = Icons.Outlined.CreditCard,
                        contentDescription = null,
                        tint = avatarTint,
                        modifier = Modifier.size(16.dp),
                    )
                    VaultItemKind.Note -> Icon(
                        imageVector = Icons.Outlined.Description,
                        contentDescription = null,
                        tint = avatarTint,
                        modifier = Modifier.size(16.dp),
                    )
                    VaultItemKind.Identity -> Icon(
                        imageVector = Icons.Outlined.Person,
                        contentDescription = null,
                        tint = avatarTint,
                        modifier = Modifier.size(16.dp),
                    )
                    VaultItemKind.SshKey -> Icon(
                        imageVector = Icons.Outlined.Terminal,
                        contentDescription = null,
                        tint = avatarTint,
                        modifier = Modifier.size(16.dp),
                    )
                    VaultItemKind.Login -> Text(
                        text = initials,
                        style = RageType.rowTitle.copy(
                            fontSize = 13.sp,
                            letterSpacing = (-0.01).em,
                        ),
                        color = avatarTint,
                    )
                }
            }

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = item.name,
                        style = RageType.rowTitle,
                        color = c.fgEmphasis,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (item.favorite) {
                        Icon(
                            imageVector = Icons.Outlined.Star,
                            contentDescription = null,
                            tint = c.warning,
                            modifier = Modifier.size(12.dp),
                        )
                    }
                }
                val sub = if (item.site.isNotBlank()) "${item.username} · ${item.site}" else item.username
                Text(
                    text = sub,
                    style = RageType.caption,
                    color = c.fgSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            if (item.rage) {
                RageChip(recipientCount = item.recipients.size)
            } else {
                Icon(
                    imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                    contentDescription = null,
                    tint = c.fgSecondary,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
    }
}

