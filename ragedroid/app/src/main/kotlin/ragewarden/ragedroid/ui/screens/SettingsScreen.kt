package ragewarden.ragedroid.ui.screens

import android.content.pm.ApplicationInfo
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.BugReport
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Usb
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Keyboard
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.LockReset
import androidx.compose.material.icons.outlined.Preview
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Upgrade
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.AppBar
import ragewarden.ragedroid.ui.components.IconBtn
import ragewarden.ragedroid.ui.components.Mono
import ragewarden.ragedroid.ui.components.RecipientPickerSheet
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

@Composable
fun SettingsScreen(
    items: ImmutableList<VaultItem> = persistentListOf(),
    recipients: ImmutableList<Recipient>? = null,
    email: String = VaultBridge.repository()?.email.orEmpty(),
    server: String = VaultBridge.repository()?.serverUrl.orEmpty(),
    activityCount: Int = 0,
    folderCount: Int = 0,
    initialDefaultRecipientIds: ImmutableList<String> = persistentListOf(),
    autofillOn: Boolean = true,
    imeOn: Boolean = false,
    onBack: () -> Unit,
    onAccount: () -> Unit,
    onAddRecipient: () -> Unit,
    onOpenRecipient: (Recipient) -> Unit,
    onRecovery: () -> Unit,
    onRecoverFromPhrase: () -> Unit = {},
    onListRecipients: () -> Unit = {},
    onFolders: () -> Unit,
    onOpenAuditLog: () -> Unit,
    onAutofillToggle: (Boolean) -> Unit = {},
    onImeToggle: (Boolean) -> Unit = {},
    onLockNow: () -> Unit = {},
    onBackfill: () -> Unit = {},
    onBulkProtect: () -> Unit = {},
    onAutofillPreview: () -> Unit = {},
    onImePreview: () -> Unit = {},
    onDebugTokenExpired: (() -> Unit)? = null,
    onSignOut: () -> Unit,
    onToast: (String) -> Unit = {},
) {
    val c = rageColors
    val context = androidx.compose.ui.platform.LocalContext.current
    val accountId = remember(context) { VaultBridge.repository()?.accountId.orEmpty() }
    // Same signal RageApp uses to decide whether to hand us onDebugTokenExpired.
    // Recomputed here rather than taken from the caller so a demo surface can
    // never reach a release build because someone forgot to gate the argument.
    val isDebuggable = remember(context) {
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
    val resolvedRecipients: ImmutableList<Recipient> = remember(recipients, context, accountId) {
        if (recipients != null) recipients
        else if (accountId.isBlank()) persistentListOf()
        else context.appEntryPoint().recipientStore().forAccount(accountId)
            .map { it.toUiRecipient() }
            .toImmutableList()
    }

    var autofill by remember { mutableStateOf(autofillOn) }
    var ime by remember { mutableStateOf(imeOn) }
    var defaultsPickerOpen by remember { mutableStateOf(false) }
    var defaultRecipientIds by remember { mutableStateOf(initialDefaultRecipientIds) }

    val itemCount = items.size
    val protectedItems = items.count { it.rage }

    val defaultRecipients = remember(defaultRecipientIds, resolvedRecipients) {
        defaultRecipientIds.mapNotNull { id -> resolvedRecipients.firstOrNull { it.id == id } }
    }

    Column(modifier = Modifier.fillMaxSize().background(c.background)) {
        AppBar(
            title = "Settings",
            leading = {
                IconBtn(
                    icon = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 32.dp),
        ) {
            AccountHero(
                email = email,
                server = server,
                itemCount = itemCount,
                protectedItems = protectedItems,
                onClick = onAccount,
            )

            SettingsSectionLabel(
                label = "Identities",
                action = {
                    Row(
                        modifier = Modifier
                            .clickable(onClick = onAddRecipient)
                            .padding(horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Add,
                            contentDescription = null,
                            tint = c.accent,
                            modifier = Modifier.size(13.dp),
                        )
                        Text(
                            text = "Add",
                            style = RageType.button.copy(fontSize = 12.5.sp),
                            color = c.accent,
                        )
                    }
                },
            )
            Card {
                if (resolvedRecipients.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                    ) {
                        Text(
                            text = "No identities enrolled yet. Tap Add above to enrol your first.",
                            style = RageType.body.copy(fontSize = 13.sp, lineHeight = 18.sp),
                            color = c.fgSecondary,
                        )
                    }
                } else {
                    resolvedRecipients.forEachIndexed { index, recipient ->
                        RecipientRow(recipient = recipient, onClick = { onOpenRecipient(recipient) })
                        if (index < resolvedRecipients.size - 1) Divider()
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Card {
                DefaultRecipientsRow(
                    selected = defaultRecipients.toImmutableList(),
                    onClick = { defaultsPickerOpen = true },
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Shield,
                    title = "Manage recipients",
                    subtitle = "List every recipient on the cross-device registry. Remove any one of them.",
                    onClick = onListRecipients,
                )
            }

            SettingsSectionLabel(label = "Vault")
            Card {
                SettingsRow(
                    icon = Icons.Outlined.Folder,
                    title = "Folders",
                    subtitle = when (folderCount) {
                        0 -> "No custom folders yet"
                        1 -> "1 folder"
                        else -> "$folderCount folders"
                    },
                    onClick = onFolders,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Description,
                    title = "Recovery phrase",
                    subtitle = "Generate a fresh 24-word recovery phrase",
                    onClick = onRecovery,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Key,
                    title = "Recover from paper backup",
                    subtitle = "Type a 24-word phrase to read items it can unlock.",
                    onClick = onRecoverFromPhrase,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.History,
                    title = "Recent unlocks",
                    subtitle = "$activityCount entries · stored on this device",
                    onClick = onOpenAuditLog,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Upgrade,
                    title = "Protect existing items",
                    subtitle = "Convert un-protected ciphers into rage-protected ones.",
                    onClick = onBackfill,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Shield,
                    title = "Bulk protect wizard",
                    subtitle = "Select items, pick recipients, and protect in bulk.",
                    onClick = onBulkProtect,
                )
            }

            SettingsSectionLabel(label = "System integration")
            Card {
                SettingsSwitchRow(
                    icon = Icons.Outlined.Bolt,
                    title = "Autofill",
                    subtitle = if (autofill) {
                        "RageDroid is the active autofill provider."
                    } else {
                        "Tap to make RageDroid the active autofill provider."
                    },
                    on = autofill,
                    onChange = {
                        autofill = it
                        onAutofillToggle(it)
                        onToast(if (it) "Autofill enabled." else "Autofill disabled.")
                    },
                )
                Divider()
                SettingsSwitchRow(
                    icon = Icons.Outlined.Keyboard,
                    title = "Quick-fill keyboard",
                    subtitle = if (ime) {
                        "A RageDroid keyboard suggests credentials inside login forms."
                    } else {
                        "Suggests credentials inline above the keys, even in apps that don't support Autofill."
                    },
                    on = ime,
                    onChange = {
                        ime = it
                        onImeToggle(it)
                        onToast(if (it) "Quick-fill keyboard enabled." else "Quick-fill keyboard disabled.")
                    },
                )
                // Demo surfaces: they render mock credentials rather than doing
                // anything to the vault, so they belong with the other
                // debug-only entries and not in a shipped build.
                if (isDebuggable) {
                    Divider()
                    SettingsRow(
                        icon = Icons.Outlined.Preview,
                        title = "Preview autofill picker",
                        subtitle = "Debug-only · what RageDroid shows when an app requests credentials.",
                        onClick = onAutofillPreview,
                    )
                    Divider()
                    SettingsRow(
                        icon = Icons.Outlined.Preview,
                        title = "Preview keyboard",
                        subtitle = "Debug-only · the quick-fill keyboard surface without leaving the app.",
                        onClick = onImePreview,
                    )
                }
            }

            SettingsSectionLabel(label = "Security")
            Card {
                SettingsRow(
                    icon = Icons.Outlined.LockReset,
                    title = "Lock now",
                    subtitle = "Require biometric or master password to re-open the vault.",
                    onClick = onLockNow,
                )
            }

            SettingsSectionLabel(label = "About")
            Card {
                SettingsRow(
                    icon = Icons.Outlined.Info,
                    title = "Version",
                    value = "0.4.1 · build 81a3",
                    onClick = null,
                )
                Divider()
                // Plain text, not a link: nothing here launches a browser, and
                // a chevron that only toasts "Opens browser" is a lie.
                SettingsRow(
                    icon = Icons.Outlined.Language,
                    title = "Source code",
                    subtitle = "github.com/eordano/ragewarden",
                    onClick = null,
                )
                Divider()
                SettingsRow(
                    icon = Icons.Outlined.Close,
                    title = "Sign out & forget device",
                    subtitle = "Wipes the encrypted vault cache from this device.",
                    danger = true,
                    onClick = onSignOut,
                )
                if (onDebugTokenExpired != null) {
                    Divider()
                    SettingsRow(
                        icon = Icons.Outlined.BugReport,
                        title = "Simulate token expiry",
                        subtitle = "Debug-only · jumps to the re-auth screen.",
                        onClick = onDebugTokenExpired,
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "RageDroid 0.4.1 · A LocalForge product\nage 1.2.0 · yubikit-android 2.5",
                style = RageType.body.copy(
                    fontSize = 13.sp,
                    lineHeight = 19.5.sp,
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic,
                    textAlign = TextAlign.Center,
                ),
                color = c.fgSecondary,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp),
            )
            Spacer(modifier = Modifier.height(12.dp))
        }
    }

    RecipientPickerSheet(
        open = defaultsPickerOpen,
        onDismiss = { defaultsPickerOpen = false },
        recipients = resolvedRecipients,
        selected = defaultRecipientIds,
        onChange = { next ->
            defaultRecipientIds = next
            onToast("Default recipients updated · ${next.size} selected")
        },
        allowEmpty = false,
        onToast = onToast,
    )
}

@Composable
private fun AccountHero(
    email: String,
    server: String,
    itemCount: Int,
    protectedItems: Int,
    onClick: () -> Unit,
) {
    val c = rageColors
    val initial = email.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 16.dp, top = 8.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.surfaceElevated, RoundedCornerShape(12.dp))
                .border(1.dp, c.border, RoundedCornerShape(12.dp))
                .clickable(onClick = onClick)
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(c.accent, RoundedCornerShape(22.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = initial,
                    style = RageType.h2.copy(fontSize = 18.sp),
                    color = c.background,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = email,
                    style = RageType.h2.copy(fontSize = 16.sp),
                    color = c.fgEmphasis,
                )
                Mono(
                    text = "$server · $itemCount items · $protectedItems protected",
                    size = 11,
                    color = c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Icon(
                imageVector = Icons.Outlined.ChevronRight,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

@Composable
private fun SettingsSectionLabel(
    label: String,
    action: (@Composable () -> Unit)? = null,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, top = 20.dp, bottom = 8.dp),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label.uppercase(),
            style = RageType.eyebrow.copy(letterSpacing = 0.08.em),
            color = c.fgSecondary,
        )
        if (action != null) action()
    }
}

@Composable
private fun SettingsRow(
    icon: ImageVector?,
    title: String,
    subtitle: String? = null,
    value: String? = null,
    danger: Boolean = false,
    onClick: (() -> Unit)?,
) {
    val c = rageColors
    val rowMod = if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(rowMod)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (icon != null) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .background(c.tile, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = if (danger) c.dangerStrong else c.accent,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = if (danger) c.dangerStrong else c.fgEmphasis,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
        if (value != null) {
            Text(
                text = value,
                style = RageType.caption.copy(fontSize = 12.5.sp),
                color = c.fgSecondary,
            )
        }
        if (onClick != null) {
            Icon(
                imageVector = Icons.Outlined.ChevronRight,
                contentDescription = null,
                tint = c.fgSecondary,
                modifier = Modifier.size(14.dp),
            )
        }
    }
}

@Composable
private fun SettingsSwitchRow(
    icon: ImageVector?,
    title: String,
    subtitle: String?,
    on: Boolean,
    onChange: (Boolean) -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onChange(!on) }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (icon != null) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .background(c.tile, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = c.accent,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = c.fgEmphasis,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = RageType.caption.copy(fontSize = 11.5.sp),
                    color = c.fgSecondary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
        ToggleSwitch(on = on, onChange = onChange)
    }
}

@Composable
private fun RecipientRow(recipient: Recipient, onClick: () -> Unit) {
    val c = rageColors
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
                .size(32.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = recipientKindIcon(recipient.kind),
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(16.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = recipient.name,
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = c.fgEmphasis,
            )
            val subtitle = if (recipient.lastUsed.isBlank()) {
                recipientKindLabel(recipient.kind)
            } else {
                "${recipientKindLabel(recipient.kind)} · ${recipient.lastUsed}"
            }
            Text(
                text = subtitle,
                style = RageType.caption.copy(fontSize = 11.5.sp),
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Icon(
            imageVector = Icons.Outlined.ChevronRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier.size(14.dp),
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DefaultRecipientsRow(
    selected: ImmutableList<Recipient>,
    onClick: () -> Unit,
) {
    val c = rageColors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .background(c.tile, RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Outlined.Shield,
                contentDescription = null,
                tint = c.accent,
                modifier = Modifier.size(16.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "Default recipients",
                style = RageType.rowTitle.copy(fontSize = 14.5.sp),
                color = c.fgEmphasis,
            )
            Text(
                text = "Every new item is encrypted to these recipients by default.",
                style = RageType.caption.copy(fontSize = 11.5.sp),
                color = c.fgSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (selected.isEmpty()) {
                Text(
                    text = "None -- new items will be unprotected. Tap to choose at least one.",
                    style = RageType.caption.copy(
                        fontSize = 12.sp,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    ),
                    color = c.dangerStrong,
                )
            } else {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    selected.forEach { recipient ->
                        Row(
                            modifier = Modifier
                                .background(c.tile, RoundedCornerShape(12.dp))
                                .border(1.dp, c.border, RoundedCornerShape(12.dp))
                                .padding(horizontal = 8.dp, vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(5.dp),
                        ) {
                            Icon(
                                imageVector = recipientKindIcon(recipient.kind),
                                contentDescription = null,
                                tint = c.accent,
                                modifier = Modifier.size(11.dp),
                            )
                            Text(
                                text = recipient.name,
                                style = RageType.caption.copy(fontSize = 11.5.sp),
                                color = c.fgEmphasis,
                            )
                        }
                    }
                }
            }
        }
        Icon(
            imageVector = Icons.Outlined.ChevronRight,
            contentDescription = null,
            tint = c.fgSecondary,
            modifier = Modifier
                .padding(top = 10.dp)
                .size(14.dp),
        )
    }
}

private fun recipientKindIcon(kind: RecipientKind): ImageVector = when (kind) {
    RecipientKind.YubiKey -> Icons.Outlined.Usb
    RecipientKind.Fido2 -> Icons.Outlined.Fingerprint
    RecipientKind.PasskeyPrf -> Icons.Outlined.Fingerprint
    RecipientKind.StrongBox -> Icons.Outlined.Memory
    RecipientKind.Recovery -> Icons.Outlined.Description
    RecipientKind.Software -> Icons.Outlined.Key
}

private fun recipientKindLabel(kind: RecipientKind): String = when (kind) {
    RecipientKind.YubiKey -> "YubiKey · PIV"
    RecipientKind.Fido2 -> "FIDO2 hmac-secret"
    RecipientKind.PasskeyPrf -> "Passkey · WebAuthn PRF"
    RecipientKind.StrongBox -> "Android StrongBox"
    RecipientKind.Recovery -> "Paper recovery"
    RecipientKind.Software -> "Software identity"
}
