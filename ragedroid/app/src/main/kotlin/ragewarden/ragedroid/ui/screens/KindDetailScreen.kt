package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.CardBody
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.IdentityBody
import ragewarden.ragedroid.ui.components.NoteBody
import ragewarden.ragedroid.ui.components.RageChip
import ragewarden.ragedroid.ui.components.SshBody
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

enum class DetailKind { Card, Note, Identity, Ssh }

private fun VaultItemKind.toDetailKind(): DetailKind = when (this) {
    VaultItemKind.Card -> DetailKind.Card
    VaultItemKind.Note -> DetailKind.Note
    VaultItemKind.Identity -> DetailKind.Identity
    VaultItemKind.SshKey -> DetailKind.Ssh
    VaultItemKind.Login -> DetailKind.Note
}

private fun kindIcon(kind: DetailKind): ImageVector = when (kind) {
    DetailKind.Card -> Icons.Outlined.CreditCard
    DetailKind.Note -> Icons.Outlined.Description
    DetailKind.Identity -> Icons.Outlined.Person
    DetailKind.Ssh -> Icons.Outlined.Terminal
}

private fun kindLabel(kind: DetailKind): String = when (kind) {
    DetailKind.Card -> "Card"
    DetailKind.Note -> "Secure note"
    DetailKind.Identity -> "Identity"
    DetailKind.Ssh -> "SSH key"
}

@Composable
fun KindDetailScreen(
    item: VaultItem,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
) {
    val c = rageColors
    val kind = item.kind.toDetailKind()

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = kindLabel(kind),
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
            trailing = {
                IconBtn(
                    icon = Icons.Outlined.Edit,
                    contentDescription = "Edit",
                    onClick = onEdit,
                )
            },
        )

        LazyColumn(modifier = Modifier.fillMaxSize()) {
            item("hero") {
                Hero(item = item, kind = kind)
            }
            item("body") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 18.dp, end = 18.dp, bottom = 24.dp),
                ) {
                    when (kind) {
                        DetailKind.Card -> CardBody(item = item, clipboard = clipboard, showToast = showToast)
                        DetailKind.Note -> NoteBody(item = item, clipboard = clipboard, showToast = showToast)
                        DetailKind.Identity -> IdentityBody(item = item, clipboard = clipboard, showToast = showToast)
                        DetailKind.Ssh -> SshBody(item = item, clipboard = clipboard, showToast = showToast)
                    }
                }
            }
        }
    }
}

@Composable
private fun Hero(item: VaultItem, kind: DetailKind) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, top = 4.dp, bottom = 18.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(
            modifier = Modifier
                .size(56.dp)
                .background(c.tile, RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = kindIcon(kind),
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(26.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = item.name,
                    style = RageType.h1.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = 22.sp,
                    ),
                    color = c.fgEmphasis,
                )
                if (item.rage) {
                    RageChip(recipientCount = item.recipients.size)
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "${kindLabel(kind).uppercase()} · ${item.folder.uppercase()}",
                style = RageType.eyebrow,
                color = c.fgSecondary,
            )
        }
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(0.dp),
    )
}
