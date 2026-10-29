package ragewarden.ragedroid.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Usb
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.RecipientRegistry
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.BackButton
import ragewarden.ragedroid.ui.components.ButtonVariant
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RageButton
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors
import ragewarden.ragedroid.ui.uiString

@Composable
fun RecipientsScreen(
    onBack: () -> Unit,
    onToast: (String) -> Unit = {},
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val c = rageColors
    val scope = rememberCoroutineScope()

    val repo: BitwardenVaultRepository? = VaultBridge.repository()
    val recipientStore: RecipientStore = remember(context) {
        context.appEntryPoint().recipientStore()
    }
    val registry = remember { RecipientRegistry(recipientStore) }
    val accountId = repo?.accountId.orEmpty()

    var refreshTick by remember { mutableStateOf(0) }
    var pendingRemoval by remember { mutableStateOf<RecipientRow?>(null) }
    var working by remember { mutableStateOf(false) }

    val rows = remember(refreshTick, repo, accountId) {
        if (repo == null || accountId.isBlank()) {
            emptyList()
        } else {
            buildRecipientRows(
                snapshotIncludingMeta = repo.snapshotWithRegistryMarker(),
                registry = registry,
                local = recipientStore.forAccount(accountId).map { it.id }.toSet(),
            )
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = stringResource(R.string.recipients_2),
            leading = { BackButton(onBack) },
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 18.dp, vertical = 12.dp),
        ) {
            if (accountId.isNotBlank() && recipientStore.isUnreadable(accountId)) {
                item("key-list-unreadable") {
                    ragewarden.ragedroid.ui.components.UnreadableKeyListCard(
                        onReset = {
                            recipientStore.resetUnreadable(accountId)
                            refreshTick += 1
                            onToast(context.getString(R.string.key_list_reset_done))
                        },
                        modifier = Modifier.padding(bottom = 12.dp),
                    )
                }
            }
            item("intro") {
                Text(
                    text = stringResource(R.string.every_recipient_enrolled_on_any_of),
                    style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 20.sp),
                    color = c.fgSecondary,
                )
                Spacer(modifier = Modifier.height(12.dp))
            }

            if (rows.isEmpty()) {
                item("empty") {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
                            .border(1.dp, c.border, RoundedCornerShape(10.dp))
                            .padding(horizontal = 14.dp, vertical = 18.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.no_recipients_in_the_cross_device),
                            style = RageType.body.copy(fontSize = 13.5.sp, lineHeight = 20.sp),
                            color = c.fgSecondary,
                        )
                    }
                }
            } else {
                items(rows.size, key = { idx -> rows[idx].id }) { idx ->
                    RecipientRowCard(
                        row = rows[idx],
                        enabled = !working,
                        onRemove = { pendingRemoval = rows[idx] },
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
        }
    }

    val targeted = pendingRemoval
    if (targeted != null) {
        AlertDialog(
            onDismissRequest = { if (!working) pendingRemoval = null },
            title = { Text(stringResource(R.string.remove_recipient)) },
            text = {
                Column {
                    Text(
                        text = stringResource(R.string.removes_from_the_cross_device_registry, targeted.displayName),
                        style = RageType.body.copy(fontSize = 14.sp, lineHeight = 20.sp),
                        color = c.fgPrimary,
                    )
                    if (targeted.local) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = stringResource(R.string.this_recipient_is_enrolled_on_this),
                            style = RageType.caption.copy(fontSize = 12.sp, lineHeight = 17.sp),
                            color = c.warning,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !working,
                    onClick = {
                        if (repo == null || accountId.isBlank()) {
                            pendingRemoval = null
                            onToast(uiString(R.string.no_active_account))
                            return@TextButton
                        }
                        working = true
                        scope.launch {
                            val unpublish = repo.unpublishRecipient(targeted.id)
                            unpublish.onSuccess {
                                if (targeted.local) {
                                    recipientStore.remove(accountId, targeted.id)
                                }
                                refreshTick += 1
                                onToast(uiString(R.string.recipient_removed))
                            }.onFailure { e ->
                                onToast(uiString(R.string.remove_failed, e.message.orEmpty()))
                            }
                            working = false
                            pendingRemoval = null
                        }
                    },
                ) { Text(if (working) stringResource(R.string.removing) else stringResource(R.string.remove)) }
            },
            dismissButton = {
                TextButton(enabled = !working, onClick = { pendingRemoval = null }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }
}

data class RecipientRow(
    val id: String,
    /**
     * `null` when the registry names a kind this build has no enum member for --
     * an entry written by a newer client. Rendered as unknown, never guessed at.
     */
    val kind: RecipientKind?,
    val displayName: String,
    val deviceLabel: String,
    val fingerprint: String,
    val local: Boolean,
    /** The registry's raw `kind` string, so an unknown one can still be named. */
    val rawKind: String = kind?.name.orEmpty(),
)

private fun buildRecipientRows(
    snapshotIncludingMeta: List<ragewarden.ragedroid.model.VaultItem>,
    registry: RecipientRegistry,
    local: Set<String>,
): List<RecipientRow> {
    val entries = registry.extractFromSnapshot(snapshotIncludingMeta)
    return entries.map { entry ->
        RecipientRow(
            id = entry.id,
            // This used to `.getOrDefault(RecipientKind.Software)`, so a kind
            // this build does not know -- a `PasskeyPrf` entry published by
            // rageterm, before the enum had that member -- was shown to the user
            // as "Software identity". That is a security claim about someone
            // else's key that this build has no basis for: it downgrades an
            // unknown, possibly hardware-backed recipient to the weakest kind we
            // have. Unknown stays unknown.
            kind = runCatching { RecipientKind.valueOf(entry.kind) }.getOrNull(),
            displayName = entry.displayName,
            deviceLabel = entry.deviceLabel,
            fingerprint = entry.fingerprintShort(),
            local = entry.id in local,
            rawKind = entry.kind,
        )
    }
}

private fun RecipientRegistry.WireEntry.fingerprintShort(): String {
    val hex = pivPubkey ?: keystorePubkey ?: fido2CredentialId
    if (hex != null && hex.length >= 12) {
        return hex.take(12).chunked(2).joinToString(":")
    }
    val armored = recoveryArmoredPubkey
    if (armored != null && armored.length >= 16) return armored.takeLast(12)
    return id.take(12)
}

@Composable
internal fun RecipientRowCard(
    row: RecipientRow,
    enabled: Boolean,
    onRemove: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.border, RoundedCornerShape(10.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(c.tile, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = recipientIcon(row.kind),
                    contentDescription = null,
                    tint = if (row.kind == null) c.warning else c.accent,
                    modifier = Modifier.size(18.dp),
                )
            }
            Spacer(modifier = Modifier.size(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = row.displayName,
                    style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                    color = c.fgEmphasis,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = if (row.local) {
                        stringResource(R.string.recipient_row_meta_local, recipientKindLabel(row.kind, row.rawKind), row.deviceLabel)
                    } else {
                        stringResource(R.string.dot_join, recipientKindLabel(row.kind, row.rawKind), row.deviceLabel)
                    },
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = if (row.kind == null) c.warning else c.fgSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Spacer(modifier = Modifier.size(8.dp))
        Mono(text = row.fingerprint, size = 11, color = c.fgSecondary)
        Spacer(modifier = Modifier.size(10.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(c.divider),
        )
        Spacer(modifier = Modifier.size(10.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
        ) {
            RageButton(
                label = stringResource(R.string.remove),
                onClick = onRemove,
                variant = ButtonVariant.Danger,
                enabled = enabled,
            )
        }
    }
}

private fun recipientIcon(kind: RecipientKind?): ImageVector = when (kind) {
    RecipientKind.YubiKey -> Icons.Outlined.Usb
    RecipientKind.Fido2 -> Icons.Outlined.Fingerprint
    RecipientKind.PasskeyPrf -> Icons.Outlined.Fingerprint
    RecipientKind.StrongBox -> Icons.Outlined.Memory
    RecipientKind.Recovery -> Icons.Outlined.Description
    RecipientKind.Software -> Icons.Outlined.Key
    null -> Icons.Outlined.Warning
}

private fun recipientKindLabel(kind: RecipientKind?, rawKind: String): String = when (kind) {
    RecipientKind.YubiKey -> uiString(R.string.yubikey_piv)
    RecipientKind.Fido2 -> uiString(R.string.fido2_hmac_secret)
    RecipientKind.PasskeyPrf -> uiString(R.string.passkey_webauthn_prf)
    RecipientKind.StrongBox -> uiString(R.string.android_strongbox)
    RecipientKind.Recovery -> uiString(R.string.paper_recovery)
    RecipientKind.Software -> uiString(R.string.software_identity)
    // Deliberately does not guess. All this build knows is the wire string.
    null -> uiString(R.string.unknown_key_type) + rawKind.takeIf { it.isNotBlank() }?.let { " ($it)" }.orEmpty()
}
