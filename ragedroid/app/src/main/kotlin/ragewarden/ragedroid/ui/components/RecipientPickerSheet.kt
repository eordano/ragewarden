package ragewarden.ragedroid.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

private enum class RecipientGroup(val label: String, val sub: String) {
    Hardware(
        label = "Hardware · tap to decrypt",
        sub = "Phishing-resistant. Most secure.",
    ),
    Device(
        label = "This device",
        sub = "Always available while signed in.",
    ),
    Recovery(
        label = "Recovery",
        sub = "Fallback if every other recipient is lost.",
    ),
}

private fun groupOf(kind: RecipientKind): RecipientGroup = when (kind) {
    RecipientKind.YubiKey, RecipientKind.Fido2, RecipientKind.PasskeyPrf -> RecipientGroup.Hardware
    RecipientKind.StrongBox, RecipientKind.Software -> RecipientGroup.Device
    RecipientKind.Recovery -> RecipientGroup.Recovery
}

@Composable
fun RecipientPickerSheet(
    open: Boolean,
    onDismiss: () -> Unit,
    recipients: ImmutableList<Recipient>,
    selected: ImmutableList<String>,
    onChange: (ImmutableList<String>) -> Unit,
    allowEmpty: Boolean = false,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    var picked by remember(open) { mutableStateOf(selected) }

    LaunchedEffect(open) {
        if (open) picked = selected
    }

    val grouped = remember(recipients) {
        recipients.groupBy { groupOf(it.kind) }
    }

    val recoveryIds = remember(recipients) {
        recipients.filter { it.kind == RecipientKind.Recovery }.map { it.id }.toSet()
    }
    val includesRecovery = picked.any { it in recoveryIds }

    Sheet(open = open, onDismiss = onDismiss, title = "Recipients") {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = "Any of the selected recipients can decrypt this item. " +
                    "Choose at least one -- without recovery you can be locked out.",
                style = RageType.body.copy(fontSize = 14.sp, lineHeight = 21.sp),
                color = c.fgSecondary,
                modifier = Modifier.padding(bottom = 16.dp),
            )

            RecipientGroup.entries.forEach { group ->
                val members = grouped[group].orEmpty()
                if (members.isEmpty()) return@forEach
                Text(
                    text = group.label.uppercase(),
                    style = RageType.eyebrow,
                    color = c.fgSecondary,
                    modifier = Modifier.padding(start = 2.dp, end = 2.dp, bottom = 6.dp),
                )
                Text(
                    text = group.sub,
                    style = RageType.body.copy(
                        fontSize = 12.5.sp,
                        lineHeight = 17.sp,
                        fontStyle = FontStyle.Italic,
                    ),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(start = 2.dp, end = 2.dp, bottom = 8.dp),
                )
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.surface, RoundedCornerShape(10.dp))
                        .border(1.dp, c.border, RoundedCornerShape(10.dp)),
                ) {
                    members.forEachIndexed { index, recipient ->
                        val on = picked.contains(recipient.id)
                        RecipientPickerRow(
                            recipient = recipient,
                            on = on,
                            onToggle = {
                                picked = if (on) {
                                    picked.filter { it != recipient.id }.toImmutableList()
                                } else {
                                    (picked + recipient.id).toImmutableList()
                                }
                            },
                        )
                        if (index < members.size - 1) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(1.dp)
                                    .background(c.divider),
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            if (!includesRecovery) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.tile, RoundedCornerShape(8.dp))
                        .border(1.dp, c.warning, RoundedCornerShape(8.dp))
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    Icon(
                        imageVector = Icons.Outlined.WarningAmber,
                        contentDescription = null,
                        tint = c.warning,
                        modifier = Modifier
                            .size(16.dp)
                            .padding(top = 2.dp),
                    )
                    Text(
                        text = "No recovery identity included. If you lose every other " +
                            "recipient, this item is gone forever.",
                        style = RageType.body.copy(fontSize = 13.sp, lineHeight = 18.sp),
                        color = c.fgPrimary,
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RageButton(
                    label = "Cancel",
                    onClick = onDismiss,
                    variant = ButtonVariant.Secondary,
                )
                val saveLabel = "Save · ${picked.size} " +
                    if (picked.size == 1) "recipient" else "recipients"
                RageButton(
                    label = saveLabel,
                    onClick = {
                        onChange(picked)
                        onToast("Recipients updated · ${picked.size} selected")
                        onDismiss()
                    },
                    enabled = allowEmpty || picked.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                    fullWidth = true,
                )
            }
        }
    }
}

@Composable
private fun RecipientPickerRow(
    recipient: Recipient,
    on: Boolean,
    onToggle: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (on) c.tile else androidx.compose.ui.graphics.Color.Transparent)
            .clickable(onClick = onToggle)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        RecipientPip(kind = recipient.kind)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = recipient.name,
                style = RageType.rowTitle.copy(fontSize = 14.sp),
                color = c.fgEmphasis,
            )
            Mono(
                text = recipient.fingerprint,
                size = 11,
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Box(
            modifier = Modifier
                .size(22.dp)
                .background(
                    if (on) c.accent else androidx.compose.ui.graphics.Color.Transparent,
                    RoundedCornerShape(4.dp),
                )
                .border(
                    1.5.dp,
                    if (on) c.accent else c.border,
                    RoundedCornerShape(4.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            if (on) {
                Icon(
                    imageVector = Icons.Outlined.Check,
                    contentDescription = null,
                    tint = c.background,
                    modifier = Modifier.size(14.dp),
                )
            }
        }
    }
}
